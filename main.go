package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	cid "github.com/aws/aws-sdk-go/service/cognitoidentity"
	"os"
)

func createPool() (*cid.IdentityPool, error){
	
	mySession := session.Must(session.NewSession())
	svc := cid.New(mySession)
	
	var poolParams cid.CreateIdentityPoolInput
	poolParams.SetAllowUnauthenticatedIdentities(false);
	
	intClientId := os.Getenv("CLIENT")
	intProviderName := os.Getenv("PROVIDER")
	intServerSideTokenCheck := true
	
	provider := []*cid.Provider {
		&cid.Provider {
			ClientId: &intClientId,
			ProviderName: &intProviderName,
			ServerSideTokenCheck: &intServerSideTokenCheck,
		},
	}
	
	poolParams.SetCognitoIdentityProviders(provider)
	poolParams.SetIdentityPoolName(os.Getenv("POOL"))
	
	pool, err := svc.CreateIdentityPool(&poolParams)
	if err != nil {
		return nil, err
	}
	
	return pool, err
	
}

func main(){
	
	fmt.Println("start")
	
	pool, err := createPool()
	if err != nil {
		panic(err)
	}
	
	fmt.Printf("%+v\n", pool)
	
}
