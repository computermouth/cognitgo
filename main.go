package main

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/sethvargo/go-password/password"
	cidp "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
	"regexp"
)

//~ func createPool() (*cidp.IdentityPool, error){
	
	//~ var poolParams cid.CreateIdentityPoolInput
	//~ poolParams.SetAllowUnauthenticatedIdentities(false);
	
	//~ intClientId := os.Getenv("CLIENT")
	//~ intProviderName := os.Getenv("PROVIDER")
	//~ intServerSideTokenCheck := true
	
	//~ provider := []*cid.Provider {
		//~ &cid.Provider {
			//~ ClientId: &intClientId,
			//~ ProviderName: &intProviderName,
			//~ ServerSideTokenCheck: &intServerSideTokenCheck,
		//~ },
	//~ }
	
	//~ poolParams.SetCognitoIdentityProviders(provider)
	//~ poolParams.SetIdentityPoolName(os.Getenv("POOL"))
	
	//~ pool, err := svc.CreateIdentityPool(&poolParams)
	//~ if err != nil {
		//~ return nil, err
	//~ }
	
	//~ return pool, err
	
//~ }

func pwMeetsCriteria(pw string) bool {
	
	findNum := regexp.MustCompile("[0-9]")
	findSpecial := regexp.MustCompile("!|#|$|%|&|(|)|,|-|.|:|;|<|=|>|@|[|]|^|_|~")
	
	log.Debugf("pw: %s", pw)
	
	if pw == "" {
		log.Debugf("pw_firstrun")
		return false
	} else if pw == strings.ToUpper(pw) {
		log.Debugf("pw_noupper")
		return false
	} else if pw == strings.ToLower(pw) {
		log.Debugf("pw_nolower")
		return false
	} else if findNum.FindAllString(pw, 1) == nil {
		log.Debugf("pw_nonumber")
		return false
	} else if findSpecial.FindAllString(pw, 1) == nil {
		log.Debugf("pw_nospecial")
		return false
	}
	
	log.Debugf("pw: %s", pw)
	
	return true
}

func genpw() string {
	
	log.Debugf("genpw_start")
	
	pw := ""
	var err error = nil
	pwlen := 12
	
	for ! pwMeetsCriteria(pw){
		
		pw, err = password.Generate(pwlen, pwlen/4, pwlen/4, false, false)
		if err != nil  {
			panic(err)
		}
	
	}
	
	log.Debugf("genpw_end")
	
	return pw
	
}

func addUser(svc *cidp.CognitoIdentityProvider, email string, username string) (*cidp.AdminCreateUserOutput, error) {
	
	log.Debugf("addUser_begin")
	
	var acui cidp.AdminCreateUserInput
	
	// DesiredDeliveryMediums
	emailDelivery := "EMAIL"
	deliveries := []*string { &emailDelivery }
	acui.SetDesiredDeliveryMediums(deliveries)
	
	// TODO: Set MessageAction to "RESEND" for
	// already existing users
	
	// TemporaryPassword
	acui.SetTemporaryPassword(genpw())
	
	// UserAttributes
	uaName := "email"
	uaValue := email
	ua := cidp.AttributeType {
		Name: &uaName,
		Value: &uaValue,
	}
	acui.SetUserAttributes( []*cidp.AttributeType{ &ua } )
	
	// UserPoolId
	acui.SetUserPoolId( os.Getenv("POOL") )
	
	// Username
	acui.SetUsername(username)
	
	out, err := svc.AdminCreateUser(&acui)
	if err != nil {
		return out, err
	}
	
	log.Debugf("addUser_end")
	
	return out, err
}

func main(){
	
	if os.Getenv("DEBUG") == "1" {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}
	
	log.Debugf("main_start")
	
	if len(os.Args) < 3 || len(os.Args) > 3 {
		log.Errorf("%s [email] [username]", os.Args[0])
		os.Exit(1)
	}
	
	mySession := session.Must(session.NewSession())
	svc := cidp.New(mySession)
	
	out, err := addUser(svc, os.Args[1], os.Args[2])
	if err != nil {
		log.Errorf("%+v", err)
	}
	
	log.Debugf("addUser out:\n%+v", out)
	
}
