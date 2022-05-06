package amon::webauthn::Web::Dispatcher;
use strict;
use warnings;
use utf8;
use String::Random;
use JSON;
use MIME::Base64;
use Digest::SHA qw(sha256_hex);
use CBOR::XS;
use Amon2::Web::Dispatcher::RouterBoom;

get '/' => sub {
    my ($c) = @_;
    return $c->render('index.tx');
};

get '/register1' => sub {
    my ($c) = @_;
    return $c->render('register1.tx');
};

post '/register2' => sub {
    my ($c) = @_;
    my $username = $c->req->parameters->{username};
    my $userId = String::Random->new->randregex('[A-Za-z0-9]{32}');
    my $challenge = String::Random->new->randregex('[A-Za-z0-9]{32}');
    $c->session->set(challenge => $challenge);
    my $PublicKeyCredentialCreationOptions = {
        rp => {
            name => 'amon rp',
            id => 'localhost'
        },
        user => {
            name => $username,
            id => $userId,
            displayName => $username
        },
        challenge => $challenge,
        pubKeyCredParams => [
            {
                type=> 'public-key',
                alg	=> -7
            },
        ]
    };
    return $c->render('register2.tx', { 
        PublicKeyCredentialCreationOptions => encode_json($PublicKeyCredentialCreationOptions)
        });
};

post '/register3' => sub {
    my ($c) = @_;
    my $response = decode_json($c->req->parameters->{cred});

    # 6. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
    my $cdata = decode_json(decode_base64($response->{response}->{clientDataJSON}));

    # 7 Verify that the value of C.type is webauthn.create.
    if(!($cdata->{type} eq 'webauthn.create')) {
        die $cdata->{type} . "is not 'webauthn.create'.";
    }

    # 8 Verify that the value of C.challenge equals the base64url encoding of options.challenge.
    my $challenge = $c->session->get('challenge');
    if(!($cdata->{challenge} eq $challenge)) {
        die "challenge unmatched.";
    }

    # 9. Verify that the value of C.origin matches the Relying Party's origin.
    if(!($cdata->{origin} eq 'http://localhost:5000')) {
        die "origin unmatched. C.origin:". $cdata->{origin};
    }

    # 10. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
    if(defined($cdata->{tokenBinding})) {
        my $tokenBindingStatus = $cdata->{tokenBinding}->{status};
        # verify token binding
    }

   # 11. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
   my $clientDataJsonHash = sha256_hex(decode_base64($response->{response}->{clientDataJSON}));

   # 12. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
   my $attestationObject = decode_cbor(decode_base64($response->{response}->{attestationObject}));

   # authData structure: https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-data
   my $authData = $attestationObject->{authData};
   use bytes;

   # 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
   my $rpIdHash = substr $authData, 0, 32;
   $rpIdHash =~ s/(.)/sprintf '%02x', ord $1/seg;
   if(!($rpIdHash eq sha256_hex('localhost'))) {
        die "rpIdHash unmatched. rpIdHash:". $rpIdHash . " expected:" . sha256_hex('localhost');
   }

    # 14. Verify that the User Present bit of the flags in authData is set.
   my $flags = substr $authData, 32, 1;
   if(!(ord($flags) & 1)) {
       # User Present is first bit.
       die "User Present flag is not on.";
   }

   # 15. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
    if(!(ord($flags) & 4)) {
       # User Verified is third bit.
       die "User Present flag is not on.";
   }

   my $signCount = substr $authData, 33, 4;
   my $attestedCredentialData = substr $authData, 37;
   my $aaguid = substr $attestedCredentialData, 0, 16;
   $aaguid =~ s/(.)/sprintf '%04x', ord $1/seg;

   my $credentialIdLength = substr $attestedCredentialData, 16, 2;
   my $credentialId = substr $attestedCredentialData, 18, ord($credentialIdLength);
   my $credentialPublicKey = substr $attestedCredentialData, 18 + ord($credentialIdLength);


   # my $attestedCredentialData = substr $authData, 39;
   # my $extensions;    
   no bytes;






    return $c->render('register3.tx', {
        cred => encode_json(
   {
       aaguid => $aaguid
   }            
        )
    });
};

post '/account/logout' => sub {
    my ($c) = @_;
    $c->session->expire();
    return $c->redirect('/');
};

1;
