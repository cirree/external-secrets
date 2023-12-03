/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package secretmanager

import (
	"context"
	"fmt"

	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/googleapis/gax-go/v2"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/api/sts/v1"
	"google.golang.org/grpc"
	"grpc.go4.org/credentials/oauth"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/constants"
	"github.com/external-secrets/external-secrets/pkg/metrics"
)

// workloadIdentityFederation holds all clients and generators needed
// to create a gcp oauth token.
type workloadIdentityFederation struct {
	iamClient         IamClient
	stsTokenGenerator stsTokenGenerator
	saTokenGenerator  saTokenGenerator
	clusterProjectID  string
}

type stsTokenGenerator interface {
	Generate(context.Context, string, string) (*oauth2.Token, error)
}

func newWorkloadIdentityFederation(ctx context.Context, projectID string) (*workloadIdentityFederation, error) {
	satg, err := newSATokenGenerator()
	if err != nil {
		return nil, err
	}
	iamc, err := newIAMClient(ctx)
	if err != nil {
		return nil, err
	}
	return &workloadIdentityFederation{
		iamClient:         iamc,
		stsTokenGenerator: newSTSTokenGenerator(),
		saTokenGenerator:  satg,
		clusterProjectID:  projectID,
	}, nil
}

func (w *workloadIdentityFederation) TokenSource(ctx context.Context, auth esv1beta1.GCPSMAuth, isClusterKind bool, kube kclient.Client, namespace string) (oauth2.TokenSource, error) {
	wif := auth.WorkloadIdentityFederation
	if wif == nil {
		return nil, nil
	}
	saKey := types.NamespacedName{
		Name:      wif.ServiceAccountRef.Name,
		Namespace: namespace,
	}

	// only ClusterStore is allowed to set namespace (and then it's required)
	if isClusterKind && wif.ServiceAccountRef.Namespace != nil {
		saKey.Namespace = *wif.ServiceAccountRef.Namespace
	}

	sa := &v1.ServiceAccount{}
	err := kube.Get(ctx, saKey, sa)
	if err != nil {
		return nil, err
	}

	idProvider := fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		auth.WorkloadIdentityFederation.ProviderProjectIDNumeric,
		auth.WorkloadIdentityFederation.PoolID,
		auth.WorkloadIdentityFederation.ProviderID)

	// GCP Workload identity default audience equals WIF provider, so setting this as default. If different allowed audience(s) is desirable, this can be set in wif.ServiceAccountRef.
	aud := idProvider
	audiences := []string{aud}
	if len(wif.ServiceAccountRef.Audiences) > 0 {
		audiences = append(audiences, wif.ServiceAccountRef.Audiences...)
	}
	gcpSA := sa.Annotations[gcpSAAnnotation]

	resp, err := w.saTokenGenerator.Generate(ctx, audiences, saKey.Name, saKey.Namespace)
	metrics.ObserveAPICall(constants.ProviderGCPSM, constants.CallGCPSMGenerateSAToken, err)
	if err != nil {
		return nil, fmt.Errorf(errFetchPodToken, err)
	}

	idBindToken, err := w.stsTokenGenerator.Generate(ctx, resp.Status.Token, idProvider)
	metrics.ObserveAPICall(constants.ProviderGCPSM, constants.CallGCPSMGenerateIDBindToken, err)
	if err != nil {
		return nil, fmt.Errorf(errFetchIBToken, err)
	}

	// If no `iam.gke.io/gcp-service-account` annotation is present the
	// identitybindingtoken will be used directly, allowing bindings on secrets
	// of the form "serviceAccount:<project>.svc.id.goog[<namespace>/<sa>]".
	if gcpSA == "" {
		return oauth2.StaticTokenSource(idBindToken), nil
	}
	gcpSAResp, err := w.iamClient.GenerateAccessToken(ctx, &credentialspb.GenerateAccessTokenRequest{
		Name:  fmt.Sprintf("projects/-/serviceAccounts/%s", gcpSA),
		Scope: secretmanager.DefaultAuthScopes(),
	}, gax.WithGRPCOptions(grpc.PerRPCCredentials(oauth.TokenSource{TokenSource: oauth2.StaticTokenSource(idBindToken)})))
	metrics.ObserveAPICall(constants.ProviderGCPSM, constants.CallGCPSMGenerateAccessToken, err)
	if err != nil {
		return nil, fmt.Errorf(errGenAccessToken, err)
	}
	return oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: gcpSAResp.GetAccessToken(),
	}), nil
}

func (w *workloadIdentityFederation) Close() error {
	if w.iamClient != nil {
		return w.iamClient.Close()
	}
	return nil
}

// Trades the kubernetes token for an Google OAuth 2.0 access token.
type gcpSTSTokenGenerator struct{}

func newSTSTokenGenerator() stsTokenGenerator {
	return &gcpSTSTokenGenerator{}
}

func (g *gcpSTSTokenGenerator) Generate(ctx context.Context, k8sToken, idProvider string) (*oauth2.Token, error) {
	stsExchangeTokenRequest := sts.GoogleIdentityStsV1ExchangeTokenRequest{
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
		Audience:           idProvider,
		Scope:              "https://www.googleapis.com/auth/cloud-platform",
		SubjectToken:       k8sToken,
	}
	gcpStsService, err := sts.NewService(context.Background(), option.WithoutAuthentication())
	if err != nil {
		return nil, fmt.Errorf(errGenAccessToken, err)
	}

	gcpStsV1Service := sts.NewV1Service(gcpStsService)

	stsToken, err := gcpStsV1Service.Token(&stsExchangeTokenRequest).Do()
	if err != nil {
		return nil, fmt.Errorf(errGenAccessToken, err)
	}

	return &oauth2.Token{
		AccessToken: stsToken.AccessToken,
		TokenType:   stsToken.TokenType,
	}, nil

}
