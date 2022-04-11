terraform {
  required_version = ">= 1.0.0"

  required_providers {
    google = ">= 3.40.0"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_project" "project" {
  project_id = var.project_id
}

resource "google_scc_source" "source" {
  count = var.source_id == null ? 1 : 0

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

data "google_cloud_identity_group_memberships" "superadmin-members" {
  count = var.superadmin_group != null ? 1 : 0
  group = var.superadmin_group
}

locals {
  all_superadmins     = [for member in data.google_cloud_identity_group_memberships.superadmin-members[0].memberships : format("\"%s\"", member.preferred_member_key[0].id)]
  all_superadmins_str = format("(%s)", join(" OR ", local.all_superadmins))
}

resource "google_monitoring_alert_policy" "alert-policies" {
  for_each = var.alerts

  project      = var.project_id
  display_name = each.value.finding
  combiner     = "OR"
  conditions {
    display_name = each.value.finding
    condition_matched_log {
      filter           = replace(replace(each.value.log_filter, "%superadmins%", local.all_superadmins_str), "%superadmin-group%", var.superadmin_group)
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

module "cloud-function" {
  source = "./modules/pubsub2inbox"

  project_id      = var.project_id
  organization_id = var.organization_id
  region          = var.region

  function_name  = var.function_name
  function_roles = ["scc-findings"]

  pubsub_topic = google_pubsub_topic.topic.id
  secret_id    = format("%s-config", var.function_name)
  config_contents = templatefile(format("%s/config.yaml", path.module), {
    scc_source = var.source_id != null ? var.source_id : google_scc_source.source[0].name
    findings   = jsonencode(var.alerts)
  })


  service_account = format("%s-sa", var.function_name)
  bucket_name     = format("%s-cf", var.function_name)
  bucket_location = var.region
}
