resource "google_service_account" "default" {
  project    = var.project_id
  account_id = var.GCP_GSA_NAME
}

resource "google_project_iam_member" "secretadmin" {
  project = var.project_id
  role    = "roles/secretmanager.admin"
  member  = "serviceAccount:${google_service_account.default.email}"
}

resource "google_project_iam_member" "service_account_token_creator" {
  project = var.project_id
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "serviceAccount:${google_service_account.default.email}"
}

resource "google_service_account_iam_member" "pod_identity" {
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[default/${var.GCP_KSA_NAME}]"
  service_account_id = google_service_account.default.name
}

resource "google_service_account_iam_member" "pod_identity_e2e" {
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[default/external-secrets-e2e]"
  service_account_id = google_service_account.default.name
}

resource "google_container_cluster" "primary" {
  project                  = var.project_id
  name                     = "${var.env}-cluster"
  location                 = var.zone
  remove_default_node_pool = true
  initial_node_count       = var.initial_node_count
  network                  = var.network
  subnetwork               = var.subnetwork
  deletion_protection      = false
  ip_allocation_policy {}
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
  resource_labels = {
    "example" = "value"
  }
}

resource "google_container_node_pool" "nodes" {
  project    = var.project_id
  name       = "${google_container_cluster.primary.name}-node-pool"
  location   = google_container_cluster.primary.location
  cluster    = google_container_cluster.primary.name
  node_count = var.node_count

  node_config {
    preemptible     = var.preemptible
    machine_type    = "n1-standard-2"
    service_account = google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}

provider "kubernetes" {
  host                   = "https://${google_container_cluster.primary.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.primary.master_auth.0.cluster_ca_certificate)
}

data "google_client_config" "default" {}

resource "kubernetes_service_account" "test" {
  metadata {
    name = var.GCP_KSA_NAME
    annotations = {
      "iam.gke.io/gcp-service-account" : "${var.GCP_GSA_NAME}@${var.project_id}.iam.gserviceaccount.com"
    }
  }
}

# Retrieve cluster's OIDC configuration for Workload identity federation testing. This data is necessary to generate 
data "http" "oidc_config" {
  url = "https://container.googleapis.com/v1/projects/${var.project_id}/locations/${google_container_cluster.primary.location}/clusters/${google_container_cluster.primary.name}/jwks"

  # Optional request headers
  request_headers = {
    Accept = "application/json"
  }
}

resource "google_iam_workload_identity_pool" "pool" {
  project                   = var.project_id
  workload_identity_pool_id = "external-secret-e2e-managed"
  display_name              = "external-secret-e2e-managed"
  description               = "Identity pool for automated test"
  disabled                  = false
}

resource "google_iam_workload_identity_pool_provider" "provider-default-audience" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "provider-default-audience"
  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
  oidc {
    issuer_uri = "https://container.googleapis.com/v1/projects/${var.project_id}/locations/${google_container_cluster.primary.location}/clusters/${google_container_cluster.primary.name}/jwks"
  }
}

resource "google_iam_workload_identity_pool_provider" "provider-custom-audience" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "provider-custom-audience"
  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
  oidc {
    allowed_audiences = ["external-secrets.io/custom-audience-test"]
    issuer_uri        = "https://container.googleapis.com/v1/projects/${var.project_id}/locations/${google_container_cluster.primary.location}/clusters/${google_container_cluster.primary.name}/jwks"
  }
}

resource "google_iam_workload_identity_pool_provider" "provider-jwk-file" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "provider-jwk-file"
  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
  oidc {
    jwks_json  = data.http.oidc_config.response_body
    issuer_uri = "https://kubernetes.svc.local"
  }
}
