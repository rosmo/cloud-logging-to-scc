# MITRE ATT&CK alerts to SCC

## Setup service account 

```sh
export SERVICE_ACCOUNT=mitre-deployer
export PROJECT=<your-project-id>
export ORGANIZATION=<your-org-id>
gcloud iam service-accounts create $SERVICE_ACCOUNT --project=$PROJECT

for role in browser cloudfunctions.developer securitycenter.sourcesAdmin pubsub.admin \
   monitoring.alertPolicyEditor monitoring.notificationChannelEditor storage.admin \
   secretmanager.admin iam.serviceAccountCreator resourcemanager.projectIamAdmin
do
     gcloud --quiet projects add-iam-policy-binding $PROJECT \
       --member="serviceAccount:${SERVICE_ACCOUNT}@${PROJECT}.iam.gserviceaccount.com" \
       --role="roles/${role}" \
       --condition=None
done

gcloud --quiet organizations add-iam-policy-binding $ORGANIZATION \
  --member="serviceAccount:${SERVICE_ACCOUNT}@${PROJECT}.iam.gserviceaccount.com" \
  --role="roles/resourcemanager.organizationAdmin"
```


