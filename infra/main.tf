# Infrastructure as Code (Terraform): deploy the container to GCP Cloud Run.
# NOT applied yet - a starting point. Usage: terraform init && terraform plan -var project_id=...
terraform {
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

variable "project_id" { type = string }
variable "region" {
  type    = string
  default = "europe-west3"
}
variable "image" { type = string } # e.g. europe-west3-docker.pkg.dev/<project>/secops/secops-triage-agents:latest

provider "google" {
  project = var.project_id
  region  = var.region
}

# Least privilege: the service runs as its own identity with no extra roles
resource "google_service_account" "secops" {
  account_id   = "secops-triage-agents"
  display_name = "SecOps triage agents"
}

resource "google_secret_manager_secret" "api_token" {
  secret_id = "secops-api-token"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "read_token" {
  secret_id = google_secret_manager_secret.api_token.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.secops.email}"
}

resource "google_cloud_run_v2_service" "secops" {
  name     = "secops-triage-agents"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  template {
    service_account = google_service_account.secops.email
    containers {
      image = var.image
      env {
        name = "API_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.api_token.secret_id
            version = "latest"
          }
        }
      }
    }
  }
}
