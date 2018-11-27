package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"github.com/aws/aws-sdk-go/aws/session"
	cidp "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/sethvargo/go-password/password"
	log "github.com/sirupsen/logrus"
	"os"
	"regexp"
	"strings"
)

var (
	secret string = os.Getenv("HASH")
	client string = os.Getenv("CLIENT")
	pool   string = os.Getenv("POOL")
)

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

	for !pwMeetsCriteria(pw) {

		pw, err = password.Generate(pwlen, pwlen/4, pwlen/4, false, false)
		if err != nil {
			panic(err)
		}

	}

	log.Debugf("genpw_end")

	return pw

}

func addUser(svc *cidp.CognitoIdentityProvider, email string, username string) (*cidp.AdminCreateUserOutput, string, error) {

	log.Debugf("addUser_begin")

	var acui cidp.AdminCreateUserInput

	// DesiredDeliveryMediums
	emailDelivery := "EMAIL"
	deliveries := []*string{&emailDelivery}
	acui.SetDesiredDeliveryMediums(deliveries)

	// TODO: Set MessageAction to "RESEND" for
	// already existing users
	acui.SetMessageAction("SUPPRESS")

	// TemporaryPassword
	tmppass := genpw()
	acui.SetTemporaryPassword(tmppass)

	// UserAttributes
	uaName := "email"
	uaValue := email
	ua := cidp.AttributeType{
		Name:  &uaName,
		Value: &uaValue,
	}
	acui.SetUserAttributes([]*cidp.AttributeType{&ua})

	// UserPoolId
	acui.SetUserPoolId(pool)

	// Username
	acui.SetUsername(username)

	out, err := svc.AdminCreateUser(&acui)

	log.Debugf("addUser_end")

	return out, tmppass, err
}

func genHash(username string) string {

	log.Debugf("genHash_begin")

	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write([]byte(username + client))
	secretHash := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	log.Debugf("genHash_end")

	return secretHash
}

func initAuth(svc *cidp.CognitoIdentityProvider, username string, tmppass string) (*cidp.AdminInitiateAuthOutput, error) {

	log.Debugf("initAuth_begin")

	var aiai cidp.AdminInitiateAuthInput

	aiai.SetAuthFlow("ADMIN_NO_SRP_AUTH")

	aiai.SetClientId(client)

	secretHash := genHash(username)

	authParams := map[string]*string{
		"USERNAME":    &username,
		"PASSWORD":    &tmppass,
		"SECRET_HASH": &secretHash,
	}
	aiai.SetAuthParameters(authParams)
	aiai.SetUserPoolId(pool)

	out, err := svc.AdminInitiateAuth(&aiai)

	log.Debugf("initAuth_end")

	return out, err
}

func setPw(svc *cidp.CognitoIdentityProvider, session string, username string, password string) (*cidp.AdminRespondToAuthChallengeOutput, error) {

	log.Debugf("setPw_begin")

	var artaci cidp.AdminRespondToAuthChallengeInput

	artaci.SetChallengeName("NEW_PASSWORD_REQUIRED")

	secretHash := genHash(username)

	responseParams := map[string]*string{
		"USERNAME":     &username,
		"NEW_PASSWORD": &password,
		"SECRET_HASH":  &secretHash,
	}
	artaci.SetChallengeResponses(responseParams)
	artaci.SetClientId(client)
	artaci.SetSession(session)
	artaci.SetUserPoolId(pool)

	out, err := svc.AdminRespondToAuthChallenge(&artaci)

	log.Debugf("setPw_end")

	return out, err
}

func sendEmail(svc *cidp.CognitoIdentityProvider, username string) (*cidp.ResendConfirmationCodeOutput, error) {
	
	log.Debugf("sendEmail_begin")
	
	var rcci cidp.ResendConfirmationCodeInput
	
	rcci.SetClientId(client)
	rcci.SetSecretHash(genHash(username))
	rcci.SetUsername(username)
	
	out, err := svc.ResendConfirmationCode(&rcci)
	
	log.Debugf("sendEmail_end")
	
	return out, err
	
}

func main() {

	if os.Getenv("DEBUG") == "1" {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	log.Debugf("main_start")

	if len(os.Args) < 5 || len(os.Args) > 5 {
		log.Errorf("%s [action] [arg01] [arg02] ...", os.Args[0])
		log.Errorf("%s  create  [email] [username] [password]", os.Args[0])
		os.Exit(1)
	}

	mySession := session.Must(session.NewSession())
	svc := cidp.New(mySession)

	switch os.Args[1] {
	case "create":
		auOut, tmppass, err := addUser(svc, os.Args[2], os.Args[3])
		if err != nil {
			log.Errorf("%+v", err)
			os.Exit(1)
		}
		log.Debugf("addUser out:\n%+v", auOut)
		
		iaOut, err := initAuth(svc, os.Args[3], tmppass)
		if err != nil {
			log.Errorf("%+v", err)
			os.Exit(1)
		}
		log.Debugf("initAuth out:\n%+v", iaOut)

		spOut, err := setPw(svc, *iaOut.Session, os.Args[3], os.Args[4])
		if err != nil {
			log.Errorf("%+v", err)
			os.Exit(1)
		}
		log.Debugf("initAuth out:\n%+v", spOut)

		seOut, err := sendEmail(svc, os.Args[3])
		if err != nil {
			log.Errorf("%+v", err)
			os.Exit(1)
		}
		log.Debugf("initAuth out:\n%+v", seOut)
	default:
		log.Errorf("invalid action '%s'", os.Args[1])

	}

}
