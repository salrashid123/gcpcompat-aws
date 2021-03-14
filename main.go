package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	sal "github.com/salrashid123/oauth2/aws"
	"google.golang.org/api/option"
)

const ()

var (
	gcpBucket               = flag.String("gcpBucket", "mineral-minutia-820-cab1", "GCS Bucket to access")
	gcpObjectName           = flag.String("gcpObjectName", "foo.txt", "GCS object to access")
	gcpResource             = flag.String("gcpResource", "//iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/providers/aws-provider-1", "the GCP resource to map")
	gcpTargetServiceAccount = flag.String("gcpTargetServiceAccount", "aws-federated@mineral-minutia-820.iam.gserviceaccount.com", "the ServiceAccount to impersonate")

	awsRegion          = flag.String("awsRegion", "us-east-1", "AWS Region")
	awsRoleArn         = flag.String("awsRoleArn", "arn:aws:iam::291738886548:role/gcpsts", "ARN of the role to use")
	awsSessionName     = flag.String("awsSessionName", "mysession", "Name of the session to use")
	awsAccessKeyID     = flag.String("awsAccessKeyID", "AKIAUH3H6EGK-redacted", "AWS access Key ID")
	awsSecretAccessKey = flag.String("awsSecretAccessKey", "YRJ86SK5qTOZQzZTI1u/cA5z5KmLT-redacted", "AWS SecretKey")
	useADC             = flag.Bool("useADC", false, "Use Application Default Credentials")
	useIAMToken        = flag.Bool("useIAMToken", false, "Use IAMCredentials Token exchange")
)

func main() {
	flag.Parse()

	if *useADC {
		/// USE ADC

		log.Printf(">>>>>>>>>>>>>>>>> Using ADC")
		ctx := context.Background()
		storageClient, err := storage.NewClient(ctx)
		if err != nil {
			log.Fatalf("Could not create storage Client: %v", err)
		}

		bkt := storageClient.Bucket(*gcpBucket)
		obj := bkt.Object(*gcpObjectName)
		r, err := obj.NewReader(ctx)
		if err != nil {
			panic(err)
		}
		defer r.Close()
		if _, err := io.Copy(os.Stdout, r); err != nil {
			panic(err)
		}
	} else {

		if *awsAccessKeyID == "" || *awsSecretAccessKey == "" {
			log.Fatalf("awsAccessKeyID, awsSecretAccessKey are required")
		}

		creds := credentials.NewStaticCredentials(*awsAccessKeyID, *awsSecretAccessKey, "")

		session, err := session.NewSession(&aws.Config{
			Credentials: creds,
		})
		if err != nil {
			log.Fatal(err)
		}

		conf := &aws.Config{
			Region:      aws.String(*awsRegion),
			Credentials: creds,
		}
		stsService := sts.New(session, conf)
		input := &sts.GetCallerIdentityInput{}
		result, err := stsService.GetCallerIdentity(input)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Original Caller Identity :" + result.GoString())

		/*
				To use a useridentity directly (i.,e not via AssumeRole), configure the permission on the service

			creds = credentials.NewStaticCredentials(*awsAccessKeyID, *awsSecretAccessKey, "")
			awsTokenSource, err := sal.AWSTokenSource(
				&sal.AwsTokenConfig{
					AwsCredential:        *creds,
					Scope:                "https://www.googleapis.com/auth/cloud-platform",
					TargetResource:       *gcpResource,
					Region:               *awsRegion,
					TargetServiceAccount: *gcpTargetServiceAccount,
					UseIAMToken:          *useIAMToken,
				},
			)
		*/

		params := &sts.AssumeRoleInput{
			RoleArn:         aws.String(*awsRoleArn),
			RoleSessionName: aws.String(*awsSessionName),
		}
		resp, err := stsService.AssumeRole(params)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Assumed user Arn: %s", *resp.AssumedRoleUser.Arn)
		log.Printf("Assumed AssumedRoleId: %s", *resp.AssumedRoleUser.AssumedRoleId)
		creds = credentials.NewStaticCredentials(*resp.Credentials.AccessKeyId, *resp.Credentials.SecretAccessKey, *resp.Credentials.SessionToken)
		conf = &aws.Config{
			Region:      aws.String(*awsRegion),
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
				TargetResource:       *gcpResource,
				Region:               *awsRegion,
				TargetServiceAccount: *gcpTargetServiceAccount,
				UseIAMToken:          *useIAMToken,
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

		bkt := storageClient.Bucket(*gcpBucket)
		obj := bkt.Object(*gcpObjectName)
		r, err := obj.NewReader(ctx)
		if err != nil {
			panic(err)
		}
		defer r.Close()
		if _, err := io.Copy(os.Stdout, r); err != nil {
			panic(err)
		}
	}
}
