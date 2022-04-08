provider "google" {
}

data "google_project" "project" {
  project_id = var.project_id
}

resource "google_scc_source" "source" {
  count = var.source_id == null ? 1 : 0

  project      = var.project_id
  display_name = var.source_name
  organization = var.organization_id
  description  = var.source_name
}


resource "google_pubsub_topic" "topic" {
  project = var.project_id
  name    = var.pubsub_topic
}

resource "google_pubsub_topic_iam_member" "topic-iam" {
  project = google_pubsub_topic.topic.project
  topic   = google_pubsub_topic.topic.name

  role   = "roles/pubsub.publisher"
  member = format("serviceAccount:service-%d@gcp-sa-monitoring-notification.iam.gserviceaccount.com", data.google_project.project.number)
}

resource "google_monitoring_notification_channel" "channel" {
  project      = var.project_id
  display_name = var.channel_name
  type         = "pubsub"
  labels = {
    topic = google_pubsub_topic.topic.id
  }
}

resource "google_monitoring_alert_policy" "alert-policies" {
  for_each = var.alerts

  project      = var.project_id
  display_name = each.value.finding
  combiner     = "OR"
  conditions {
    display_name = each.value.finding
    condition_matched_log {
      filter           = each.value.log_filter
      label_extractors = each.value.label_extractors
    }
  }

  notification_channels = [google_monitoring_notification_channel.channel.name]
  alert_strategy {
    notification_rate_limit {
      period = each.value.interval
    }
  }
}

data "template_file" "function-config" {
  template = file("${path.module}/config.yaml")
  vars = {
    scc_source = var.source_id != null ? var.source_id : google_scc_source.source[0].name
    findings   = jsonencode(var.alerts)
  }
}

module "cloud-function" {
  source = "./modules/pubsub2inbox"

  project_id      = var.project_id
  organization_id = var.organization_id
  region          = var.region

  function_name  = var.function_name
  function_roles = ["scc-findings"]

  pubsub_topic    = google_pubsub_topic.topic.id
  secret_id       = format("%s-config", var.function_name)
  config_contents = data.template_file.function-config.rendered

  service_account = format("%s-sa", var.function_name)
  bucket_name     = format("%s-cf", var.function_name)
  bucket_location = var.region
}
