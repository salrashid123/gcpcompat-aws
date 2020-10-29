package main

import (
	"context"
	"io"
	"log"
	"os"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	sal "github.com/salrashid123/oauth2/google"
	"google.golang.org/api/option"
)

const (
	gcpBucketName  = "mineral-minutia-820-cab1"
	gcpObjectName  = "foo.txt"
	awsRegion      = "us-east-1"
	awsRoleArn     = "arn:aws:iam::291738886548:role/gcpsts"
	awsSessionName = "mysession"
)

var ()

func main() {

	AWS_ACCESS_KEY_ID := "AKIAUH3H6-redacted"
	AWS_SECRET_ACCESS_KEY := "K61ws18wCEOqu8nS7tcM3M4-redacted"

	creds := credentials.NewStaticCredentials(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "")

	session, err := session.NewSession(&aws.Config{
		Credentials: creds,
	})
	if err != nil {
		log.Fatal(err)
	}

	conf := &aws.Config{
		Region:      aws.String(awsRegion),
		Credentials: creds,
	}
	stsService := sts.New(session, conf)
	input := &sts.GetCallerIdentityInput{}
	result, err := stsService.GetCallerIdentity(input)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Original Caller Identity :" + result.GoString())

	params := &sts.AssumeRoleInput{
		RoleArn:         aws.String(awsRoleArn),
		RoleSessionName: aws.String(awsSessionName),
	}
	resp, err := stsService.AssumeRole(params)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Assumed user Arn: %s", *resp.AssumedRoleUser.Arn)
	log.Printf("Assumed AssumedRoleId: %s", *resp.AssumedRoleUser.AssumedRoleId)
	creds = credentials.NewStaticCredentials(*resp.Credentials.AccessKeyId, *resp.Credentials.SecretAccessKey, *resp.Credentials.SessionToken)
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

	/*
				   To use a useridentity directly (i.,e not via AssumeRole), configure the permission
				   gcloud iam service-accounts add-iam-policy-binding aws-federated@$PROJECT_ID.iam.gserviceaccount.com   \
				  --role roles/iam.workloadIdentityUser \
				  --member "principal://iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:iam::291738886548:user/svcacct1"
			     then use the AWS Credential without AssumeRole
		   	creds = credentials.NewStaticCredentials(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "")
	*/

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

	tok, err := awsTokenSource.Token()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("AWS Derived GCP access_token: %s\n", tok.AccessToken)

	ctx := context.Background()
	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(awsTokenSource))
	if err != nil {
		log.Fatalf("Could not create storage Client: %v", err)
	}

	bkt := storageClient.Bucket(gcpBucketName)
	obj := bkt.Object(gcpObjectName)
	r, err := obj.NewReader(ctx)
	if err != nil {
		panic(err)
	}
	defer r.Close()
	if _, err := io.Copy(os.Stdout, r); err != nil {
		panic(err)
	}

}
