## Exchange AWS Credentials for GCP Credentials using GCP STS Service

Sample procedure and referenced library that will exchange a long term or short term AWS credential for a GCP credential.

You can use the GCP credential then to access any service the mapped principal has GCP IAM permissions on.

This repo is the first part that explores how to use the [workload identity federation](https://cloud.google.com/iam/docs/access-resources-aws) capability of GCP which allows for external principals (AWS,Azure or arbitrary OIDC provider) to map to a GCP credential.

The two procedures described in this repo will acquire a Google Credential as described here:
 - [https://cloud.google.com/iam/docs/access-resources-aws#generate](https://cloud.google.com/iam/docs/access-resources-aws#generate)

The "Automatic" way is recommended and is supported by Google

The "Manual" way is also covered in this repo but I decided to wrap the steps for that into my own library here [github.com/salrashid123/oauth2/google](https://github.com/salrashid123/oauth2#usage-aws) which surfaces the credential as an [oauth2.TokenSource](https://godoc.org/golang.org/x/oauth2#TokenSource) for use in any GCP cloud library.    

You can certainly use either procedure but the Automatic way is included with the library.  The Manual way can be done by hand but the wrapped library I'll describe here is not officially supported


The followup samples will demonstrate federation w/ Azure and an arbitrary OIDC provider (okta or Google Cloud Identity Platform)


>> This repository is not supported by Google

>> `salrashid123/oauth2/google` is also not supported by Google


for OIDC based exchanges, see
-[Exchange Generic OIDC Credentials for GCP Credentials using GCP STS Service](https://github.com/salrashid123/gcpcompat-oidc)

---

### Workload Federation - AWS

GCP now surfaces a `STS Service` that will exchange one set of tokens for another.  These initial tokens can be either 3rd party or google `access_tokens` that are [downscoped](https://github.com/salrashid123/downscoped_token) (i.,e attenuated in permission set).

The endpoint rest specifications for the STS service is [here](https://cloud.google.com/iam/docs/reference/sts/rest/v1beta/TopLevel/token)

To use this, you need both a GCP and AWS project and the ability to create user/service accounts and then apply permissions on those to facilitate the mapping.


#### AWS

There are two types of AWS creds this repo demonstrates:  

- Manual Exchange:
  In this you manually do all the steps of exchanging `AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY` for a federated token and then finally use that token

- Automatic Exchange
  In this you use the google cloud client libraries to do all the heavy lifting.  This is the recommended approach


>> It is recommended to do the manual first just to understand this capability and then move onto the automatic

#### Manual Exchange

On the AWS side, you need to configure a user, then allow it to `AssumeRole` to derive a short-term token.  You do not need to go the extra step to assumeRole but this example shows best-practices for short-lived tokens.

1. Create AWS user
  In this case, the user is `"arn:aws:iam::291738886548:user/svcacct1"` with uid=`AIDAUH3H6EGKDO36JYJH3`

```bash
export AWS_ACCESS_KEY_ID=redacted 
export AWS_SECRET_ACCESS_KEY=redacted
aws sts get-caller-identity
{
    "UserId": "AIDAUH3H6EGKDO36JYJH3",
    "Account": "291738886548",
    "Arn": "arn:aws:iam::291738886548:user/svcacct1"
}
```

![images/aws_user.png](images/aws_user.png)


2. Define Role

Allow the user to assume an AWS role.

In this case, the new role is `arn:aws:sts::291738886548:assumed-role/gcpsts/mysession`


```bash
$ aws sts assume-role --role-arn arn:aws:iam::291738886548:role/gcpsts --role-session-name mysession
{
    "Credentials": {
        "AccessKeyId": "ASIAUH3H6EGKHQ-redacted",
        "SecretAccessKey": "WgsIFtkz4mzb9ArKlds7ZFZDQEe-redacted",
        "SessionToken": "FwoGZXIvYXdzEFUaDCAJrrWlFMoH//c/fyKtAaI9f7Sfj7gVlYknoy78ScUB721MUs+GJRQIarlyse7p9WZmY3uF1UqoFcHx6N2jfNGdfylJaIayOSDRDTIMA+7a2r44WBi4K1CbFOGBIcPMspSsOcNTOmvrlfEV3O7OCDXQLEf8R9f6NCMXYfruoFG4SBBp90o/oEFam7A4BqiesGuzq0OVa8EyzmYiF7cKdUzjh+MMsQBFJ1q/6l5DeGC2a3Syx9AAYLKCKV3bKM3YxfwFMi2WtSO50zj9B4ZeI2xZN8/Xc6rxXp43GcBPOenY-redacted",
        "Expiration": "2020-10-22T12:26:05+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAUH3H6EGKHZUSB4BC5:mysession",
        "Arn": "arn:aws:sts::291738886548:assumed-role/gcpsts/mysession"
    }
}
```

![images/aws_role_trust.png](images/aws_role_trust.png)


3.  Verify Role change

Use the assumed roles token to confirm the change
```bash
export AWS_ACCESS_KEY_ID=ASIAUH3H6EG-redacted
export AWS_SECRET_ACCESS_KEY=pyDAMjC+aoDT7wWE5MbVCw9j-redacted
export AWS_SESSION_TOKEN=FwoGZXIvYXdzEFkaDLrbiqp6wyx3FLWdnSKtARKDfX3oZmHa/1NwhHGABJEKGE25wpY8TvyrYr/XHCDUCsZzhvI+mESxf3N5fQcpqu6PCmhoPXL3KUUAk2Xgx76qdRFx+UX9w+7uvCWejZ3muF1a9eTlfiLaXrYWd4O/3Go//eDHKtKESd7LaJcVzvv3egGvoDR/IORkk5aCr7Bs4/uAO2W2rud4QnUQvR/PdLNakTEa352YdVrOTAjBIK3Ya9FLWJddC93za7LVKKXAxvwFMi3fjg1gKHsCccPMzzLba0vVSeQfAqV+KgW3Iaktg5h-redacted


$ aws sts get-caller-identity
{
    "UserId": "AROAUH3H6EGKHZUSB4BC5:mysession",
    "Account": "291738886548",
    "Arn": "arn:aws:sts::291738886548:assumed-role/gcpsts/mysession"
}
```

### GCP

Switch to the GCP account


1. Create Service Account

Create a service account the AWS one will map to and grant this service account permissions on something (eg, gcs bucket)

```bash
export PROJECT_ID=`gcloud config get-value core/project`
export PROJECT_NUMBER=`gcloud projects describe $PROJECT_ID --format='value(projectNumber)'`


gcloud iam service-accounts create aws-federated

gsutil mb gs://$PROJECT-mybucket
echo fooooo > foo.txt
gsutil cp foo.txt gs://$PROJECT-mybucket
gsutil iam ch serviceAccount:aws-federated@$PROJECT.iam.gserviceaccount.com:objectViewer gs://$PROJECT-mybucket
```


There are two option on how you want to map identities:  Either individual users and roles with sessions or the assume-role name itself.

For individual users, follow (3), groups (4)

3. Individual  (for exact match on arn->subject (`principal://`))

The following commands below we are specifically mapping an arn to a subject.  That is, it will match for exactly

* `"arn:aws:iam::291738886548:user/svcacct1"`
* `"arn:aws:sts::291738886548:assumed-role/gcpsts/mysession"`

- First create a workflow identity pool 

```bash
gcloud beta iam workload-identity-pools create aws-pool-1 \
    --location="global" \
    --description="AWS " \
    --display-name="AWS Pool"
```

- Define aws-provider

Define the aws-provider associated with that pool using your AWS AccountID (in this case its `291738886548`). The `attribute-mapping=` sections are the default mapping that does the actual translation from the AWS `getCallerIdentity()` claim back to a GCP principal.  
You can define other mappings but we're using the default

```bash
gcloud beta iam workload-identity-pools providers create-aws aws-provider-1  \
   --workload-identity-pool="aws-pool-1"     --account-id="291738886548"   \
   --location="global"
```

(note, we are using the [default mapping](https://cloud.google.com/iam/docs/access-resources-aws#add-aws)  `attribute-mapping="google.subject=assertion.arn,attribute.aws_role=..."`)

- Grant WorkloadIdentity Pool to use SA

Now grant the mapped identity permissions to assume the actual GCP service account.

In the example below, principal that can assume the AWS Role of `arn:aws:sts::291738886548:assumed-role/gcpsts/mysession` will be allowed to impersonate `aws-federated@$PROJECT.iam.gserviceaccount.com`

```bash
gcloud iam service-accounts add-iam-policy-binding aws-federated@$PROJECT_ID.iam.gserviceaccount.com   \
    --role roles/iam.workloadIdentityUser \
    --member "principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:sts::291738886548:assumed-role/gcpsts/mysession"
```

4. Group  (for exact match on arn->subject (`principalSet://`))

Note the command below we are specifically mapping the Role

* `"arn:aws:sts::291738886548:assumed-role/gcpsts"`

- Define identity-pool

We will create a new identity pool here just to test

```bash
gcloud beta iam workload-identity-pools create aws-pool-2 \
    --location="global" \
    --description="AWS " \
    --display-name="AWS Pool 2"
```
- Define aws-provider

```bash
gcloud beta iam workload-identity-pools providers create-aws aws-provider-2  \
   --workload-identity-pool="aws-pool-2"     --account-id="291738886548"   \
   --location="global" 
```

(note, we using the default mapping      `attribute-mapping` of `"google.subject=assertion.arn"` and `attribute.aws_role=<AWS Role>`)

- Grant WorkloadIdentity Pool to use SA

Note, we are using `principalSet://`

```bash
gcloud iam service-accounts add-iam-policy-binding aws-federated@$PROJECT_ID.iam.gserviceaccount.com   \
    --role roles/iam.workloadIdentityUser \
    --member "principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/aws-pool-2/attribute.aws_role/arn:aws:sts::291738886548:assumed-role/gcpsts" 
```

---

You should end up with IAM bindings on the service account and on the GCS Bucket itself

```bash
$ gcloud iam service-accounts get-iam-policy aws-federated@$PROJECT_ID.iam.gserviceaccount.com  
bindings:
- members:
  - principal://iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:iam::291738886548:user/svcacct1
  - principal://iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:sts::291738886548:assumed-role/gcpsts/mysession
  - principalSet://iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-2/attribute.aws_role/arn:aws:sts::291738886548:assumed-role/gcpsts
  role: roles/iam.workloadIdentityUser
version: 1

$ gcloud projects get-iam-policy $PROJECT_ID
role: roles/storage.admin
- members:
  - principal://iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:iam::291738886548:user/svcacct1
  - principal://iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:sts::291738886548:assumed-role/gcpsts/mysession
  - principalSet://iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-2/attribute.aws_role/arn:aws:sts::291738886548:assumed-role/gcpsts
```

![images/gcp_iam.png](images/gcp_iam.png)


Verify configurations by list

```bash
$ gcloud beta iam workload-identity-pools list --location=global


$ gcloud beta iam workload-identity-pools providers list --workload-identity-pool=aws-pool-1 --location=global
```


### Automatic Exchange

With the automatic exchange, the GCP cloud auth libraries do all these steps for you.

See [generate automatic](https://cloud.google.com/iam/docs/access-resources-aws#generate-automatic)


For this to work, you must have previously setup the the `aws-federated@$PROJECT_ID.iam.gserviceaccount.com` service account and gave it permissions to the GCS object.  You should have also configured the `aws-provider-1` configurations


First step is to generate the client library helper file which will act as the `APPLICATION_DEFAULT_CREDENTIAL`

```bash
gcloud beta iam workload-identity-pools create-cred-config \
    projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/aws-pool-1/providers/aws-provider-1 \
    --service-account=aws-federated@$PROJECT_ID.iam.gserviceaccount.com \
    --output-file=sts-creds.json \
    --aws
```

It should look something like this:

```json
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/providers/aws-provider-1",
  "subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "environment_id": "aws1",
    "region_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone",
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials",
    "regional_cred_verification_url": "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
  },
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/aws-federated@mineral-minutia-820.iam.gserviceaccount.com:generateAccessToken"
}
```

Copy the `sts-creds.json` file to the EC2 instance

On the EC2 instance, make sure it has a role binding:

```bash
[root@ip-172-31-28-179 test]# aws sts get-caller-identity
{
    "Account": "291738886548", 
    "UserId": "AROAUH3H6EGKM3W5BCPKR:i-01eb8a107a2026dcd", 
    "Arn": "arn:aws:sts::291738886548:assumed-role/ec2role/i-01eb8a107a2026dcd"
}
```

Now Map that AWS role to the service account so it can get a token on its behalf

```bash
gcloud iam service-accounts add-iam-policy-binding aws-federated@$PROJECT_ID.iam.gserviceaccount.com   \
    --role roles/iam.workloadIdentityUser \
    --member "principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:sts::291738886548:assumed-role/ec2role/i-01eb8a107a2026dcd"
```

You should end up with IAM bindings on the service account and on the GCS Bucket itself similar to above

```bash
$ gcloud iam service-accounts get-iam-policy aws-federated@$PROJECT_ID.iam.gserviceaccount.com  
bindings:
- members:
  - principal://iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:sts::291738886548:assumed-role/ec2role/i-01eb8a107a2026dcd
  role: roles/iam.workloadIdentityUser
version: 1

$ gcloud projects get-iam-policy $PROJECT_ID
role: roles/storage.admin
- members:
  - principal://iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:sts::291738886548:assumed-role/ec2role/i-01eb8a107a2026dcd
```

---
### Test Automatic

Finally, on the EC2 instance, invoke the client provided in this repo:

```bash
export GOOGLE_APPLICATION_CREDENTIALS=`pwd`/sts-creds.json
# go run main.go    --gcpBucket mineral-minutia-820-cab1    --gcpObjectName foo.txt    --useADC
2021/03/10 22:05:36 >>>>>>>>>>>>>>>>> Using ADC
FOOOOO
```

the `FOOOO` is ofcourse our file

---

### Test Manual

Edit `main.go` and specify the AWS Tokens and GCS buckets you have setup

- Flags:
```golang
	gcpBucket               = flag.String("gcpBucket", "mineral-minutia-820-cab1", "GCS Bucket to access")
	gcpObjectName           = flag.String("gcpObjectName", "foo.txt", "GCS object to access")
	gcpResource             = flag.String("gcpResource", "//iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/providers/aws-provider-1", "the GCP resource to map")
	gcpTargetServiceAccount = flag.String("gcpTargetServiceAccount", "aws-federated@mineral-minutia-820.iam.gserviceaccount.com", "the ServiceAccount to impersonate")

	awsRegion          = flag.String("awsRegion", "us-east-1", "AWS Region")
	awsRoleArn         = flag.String("awsRoleArn", "arn:aws:iam::291738886548:role/gcpsts", "ARN of the role to use")
  awsSessionName     = flag.String("awsSessionName", "mysession", "Name of the session to use")
 	useADC             = flag.Bool("useADC", false, "Use Application Default Credentials")
	awsAccessKeyID     = flag.String("awsAccessKeyID", "AKIAUH3H6EGKE-redacted", "AWS access Key ID")
	awsSecretAccessKey = flag.String("awsSecretAccessKey", "YRJ86SK5qTOZQzZTI1u/cA5z5KmLT-redacted", "AWS SecretKey")

	useIAMToken = flag.Bool("useIAMToken", false, "Use IAMCredentials Token exchange")
```

- as `subject (principal://`)`

```bash
$ go run main.go \
   --gcpBucket mineral-minutia-820-cab1 \
   --gcpObjectName foo.txt \
   --gcpResource //iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/aws-pool-1/providers/aws-provider-1 \
   --gcpTargetServiceAccount aws-federated@$PROJECT_ID.iam.gserviceaccount.com \
   --useIAMToken \
   --awsRegion us-east-1 \
   --awsRoleArn arn:aws:iam::291738886548:role/gcpsts \
   --awsSessionName mysession \
   --awsAccessKeyID AKIAUH3H6EGKER-redacted \
   --awsSecretAccessKey YRJ86SK5qTOZQzZTI1u-redacted 
 
2020/10/22 15:32:50 Original Caller Identity :{
  Account: "291738886548",
  Arn: "arn:aws:iam::291738886548:user/svcacct1",
  UserId: "AIDAUH3H6EGKDO36JYJH3"
}
2020/10/22 15:32:50 Assumed user Arn: arn:aws:sts::291738886548:assumed-role/gcpsts/mysession
2020/10/22 15:32:50 Assumed AssumedRoleId: AROAUH3H6EGKHZUSB4BC5:mysession
2020/10/22 15:32:50 New Caller Identity :{
  Account: "291738886548",
  Arn: "arn:aws:sts::291738886548:assumed-role/gcpsts/mysession",
  UserId: "AROAUH3H6EGKHZUSB4BC5:mysession"
}
2020/10/22 15:32:51 AWS Derived GCP access_token: ya29.c.KpUD4ge5T4NtKAvjbMvOm2DsB6L28hTdrwtAV3Ts-redacted

fooooo
```
the first part uses the static token, the second part assumes the role, the third part exchanges the token for a GCP one...finally a _standard_ Google Cloud Storage library is used to download and object using the derived credentials.


- as `role (principalSet://`)`
 (change to use `aws-pool-2` and `aws-provider-2`)

```
$ go run main.go \
   --gcpBucket mineral-minutia-820-cab1 \
   --gcpObjectName foo.txt \
   --gcpResource //iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/aws-pool-2/providers/aws-provider-2 \
   --gcpTargetServiceAccount aws-federated@$PROJECT_ID.iam.gserviceaccount.com \
   --useIAMToken \
   --awsRegion us-east-1 \
   --awsRoleArn arn:aws:iam::291738886548:role/gcpsts \
   --awsSessionName mysession \
   --awsAccessKeyID AKIAUH3H6EGKER-redacted \
   --awsSecretAccessKey YRJ86SK5qTOZQzZTI1u/cA5z5KmLTw-redacted 
```

### Using Federated or IAM Tokens

GCP STS Tokens can be used directly against a few GCP services as described here

Skip step `(5)` of [Exchange Token](https://cloud.google.com/iam/docs/access-resources-aws#exchange-token)

What that means is you can skip the step to exchange the GCP Federation token for an Service Account token and _directly_ apply IAM policies on the resource.

This not only saves the step of running the exchange but omits the need for a secondary GCP service account to impersonate.

To use GCS, allow either the Assumed Role or AWS User access to the resource.  In this case `storage.objectAdmin` access:

To use Federated tokens, use remove the `--useIAMToken` flag


```bash
# principal://
gcloud projects add-iam-policy-binding $PROJECT_ID  \
 --member "principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:sts::291738886548:assumed-role/gcpsts/mysession" \
   --role roles/storage.objectAdmin

gcloud projects add-iam-policy-binding $PROJECT_ID  \
    --member "principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:iam::291738886548:user/svcacct1"\
      --role roles/storage.objectAdmin

# principalSet://
gcloud projects add-iam-policy-binding $PROJECT_ID  \
 --member "principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/aws-pool-2/attribute.aws_role/arn:aws:sts::291738886548:assumed-role/gcpsts" \
   --role roles/storage.objectAdmin
```

Set `UseIAMToken:  false` in the go code


>> NOTE: the GCP "Automatic" libraries always use impersonation...they do not use Federated tokens directly!

### Logging

Depending on the mode you used `UseIAMToken` flag in code, you may either see the IAM service account impersonated then access the GCS resource, or the AWS principal directly.

- `UseIAMToken:  true`:
   In this mode, the AWS credential is exchanged for a GCP STS and then the GCP STS is again exchanged for a GCP ServiceAccount Token. 
      `AWS Creds` -> `GCP STS (workload pool)` -> `GCP IAM (service_account)` -> `GCS`

   The net result is you see the iam exchange but the original AWS caller is hidden in the GCSlogs
   The following shows the logs emitted if using AssumeRole

![images/gcp_gcs_data_access.png](images/gcp_gcs_data_access.png)

![images/gcp_iam_audit_logs.png](images/gcp_iam_audit_logs.png)

- `UseIAMToken:  false`:
   In this mode, the AWS credential is exchanged for a GCP STS creds and then directly against a GCP Resource
     `AWS Creds` -> `GCP STS (workload pool)` -> `GCS` 

   The following logs shows the dataaccess logs when accessed directly as `arn:aws:iam::291738886548:user/svcacct1`:

![images/gcs_logs_federated.png](images/gcs_logs_federated.png)

>> UseIAMToken=false only works on certain GCP resources.

### Direct AWS Credentials

 To use a useridentity directly (i.,e not via AssumeRole), configure the permission
 ```bash
	   gcloud iam service-accounts add-iam-policy-binding aws-federated@$PROJECT_ID.iam.gserviceaccount.com   \
	  --role roles/iam.workloadIdentityUser \
	  --member "principal://iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:iam::291738886548:user/svcacct1" 
```

and use directly, eg:

```golang
  creds = credentials.NewStaticCredentials(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "")
	conf = &aws.Config{
		Region:      aws.String(awsRegion),
		Credentials: creds,
	}
	stsService = sts.New(session, conf)
	input = &sts.GetCallerIdentityInput{}
	result, err = stsService.GetCallerIdentity(input)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("New Caller Identity :" + result.GoString())

	awsTokenSource, err := sal.AWSTokenSource(
		&sal.AwsTokenConfig{
			AwsCredential:        *creds,
			Scope:                "https://www.googleapis.com/auth/cloud-platform",
			TargetResource:       "//iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/providers/aws-provider-1",
			Region:               "us-east-1",
            TargetServiceAccount: "aws-federated@mineral-minutia-820.iam.gserviceaccount.com",
            UseIAMToken:          true,
		},
	)        
```