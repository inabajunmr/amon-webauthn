package amon::webauthn::Web::Dispatcher;
use strict;
use warnings;
use utf8;
use String::Random;
use JSON;
use MIME::Base64;
use MIME::Base64::URLSafe;
use Digest::SHA qw(sha256_hex sha256);
use CBOR::XS;
use Crypt::PK::ECC;
use Amon2::Web::Dispatcher::RouterBoom;
use Log::Minimal;
use Data::Dumper;

# key is credential id.
our $CREDENTIAL_DB = {};

get '/' => sub {
    my ($c) = @_;
    return $c->render('index.tx');
};

get '/register1' => sub {
    my ($c) = @_;
    return $c->render('register1.tx');
};

post '/register2' => sub {
    my ($c)      = @_;
    my $username = $c->req->parameters->{username};
    my $userId   = String::Random->new->randregex('[A-Za-z0-9]{32}');
    $c->session->set( username => $username );
    my $challenge = String::Random->new->randregex('[A-Za-z0-9]{32}');
    $c->session->set( challenge => $challenge );
    my $PublicKeyCredentialCreationOptions = {
        rp => {
            name => 'amon rp',
            id   => 'localhost'
        },
        user => {
            name        => $username,
            id          => $userId,
            displayName => $username
        },
        challenge        => $challenge,
        pubKeyCredParams => [
            {
                type => 'public-key',
                alg  => -7
            },
        ],
        attestation => 'direct',
        authenticatorSelection => {
            userVerification => 'discouraged'
        }
    };
    return $c->render(
        'register2.tx',
        {
            PublicKeyCredentialCreationOptions =>
              encode_json($PublicKeyCredentialCreationOptions)
        }
    );
};

post '/register3' => sub {
    my ($c) = @_;
    my $response = decode_json( $c->req->parameters->{cred} );

    # 6. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
    my $cdata =
      decode_json( decode_base64( $response->{response}->{clientDataJSON} ) );

    # 7 Verify that the value of C.type is webauthn.create.
    if ( !( $cdata->{type} eq 'webauthn.create' ) ) {
        die $cdata->{type} . "is not 'webauthn.create'.";
    }

    # 8 Verify that the value of C.challenge equals the base64url encoding of options.challenge.
    my $challenge = $c->session->get('challenge');
    if ( !( $cdata->{challenge} eq $challenge ) ) {
        die "challenge unmatched.";
    }

    # 9. Verify that the value of C.origin matches the Relying Party's origin.
    if ( !( $cdata->{origin} eq 'http://localhost:5000' ) ) {
        die "origin unmatched. C.origin:" . $cdata->{origin};
    }

    # 10. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
    if ( defined( $cdata->{tokenBinding} ) ) {
        my $tokenBindingStatus = $cdata->{tokenBinding}->{status};
        # verify token binding
    }

    # 11. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
    my $clientDataJsonHash =
      sha256_hex( decode_base64( $response->{response}->{clientDataJSON} ) );

    # 12. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
    my $attestationObject = decode_cbor(
        decode_base64( $response->{response}->{attestationObject} ) );

    # authData structure: https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-data
    my $authData = $attestationObject->{authData};
    use bytes;

    # 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
    my $rpIdHash = substr $authData, 0, 32;
    $rpIdHash =~ s/(.)/sprintf '%02x', ord $1/seg;
    if ( !( $rpIdHash eq sha256_hex('localhost') ) ) {
        die "rpIdHash unmatched. rpIdHash:"
          . $rpIdHash
          . " expected:"
          . sha256_hex('localhost');
    }

    # 14. Verify that the User Present bit of the flags in authData is set.
    my $flags = unpack( 'C', substr $authData, 32, 1 );
    if ( !( $flags & 1 ) ) {
        # User Present is first bit.
        die "User Present flag is not on.";
    }

    # 15. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
    # if ( !( $flags & 4 ) ) {
    #     # User Verified is third bit.
    #     die "User Present flag is not on.";
    # }
    my $signCount = substr $authData, 33, 4;

    if ( !( $flags & 64 ) ) {
        # Attested credential data included.
        die "AT flag is not on.";
    }
    my $aaguid = substr $authData, 37, 16;
    $aaguid =~ s/(.)/sprintf '%02x', ord $1/seg;
    my $credentialIdLength = unpack( 'n', substr $authData, 53, 2 );
    my $credentialId       = substr $authData, 55, $credentialIdLength;
    my ( $credentialPublicKey, $length ) =
      CBOR::XS->new->decode_prefix( substr $authData,
        55 + $credentialIdLength );
    my $credentialPublicKeyRaw = substr $authData, 55 + $credentialIdLength,
      $length;

    # 16. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
    # A COSE Key structure: https://datatracker.ietf.org/doc/html/rfc8152#section-7
    my $alg = $credentialPublicKey->{'3'};
    if ( $alg != -7 ) {
        die "alg is only allowed -7. alg:$alg.";
    }

    # 17. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
    # TODO

    # 18 ~ 20. verify attestation
    # TODO

    # 21. Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
    if ( $credentialIdLength >= 1023 ) {
        die
          "The length of credentialId is too long. length:$credentialIdLength.";
    }

    # 22. Verify that the credentialId is not yet registered for any user. If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.
    if ( exists( $CREDENTIAL_DB->{$credentialId} ) ) {
        die "This credential:$credentialId is already registered.";
    }

    # # 23. If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the user account that was denoted in options.user:
    my $username = $c->session->get('username');
    $CREDENTIAL_DB->{$credentialId} =
      { pubKey => $credentialPublicKeyRaw, username => $username };

    # 24. If the attestation statement attStmt successfully verified but is not trustworthy per step 20 above, the Relying Party SHOULD fail the registration ceremony.
    # TODO

    return $c->render(
        'register3.tx',
        {
            cred => encode_json( $CREDENTIAL_DB->{$credentialId} )
        }
    );
    no bytes;
};

get '/login1' => sub {
    my ($c) = @_;
    return $c->render('login1.tx');
};

post '/login2' => sub {
    my ($c)      = @_;
    my $username = $c->req->parameters->{username};
    $c->session->set( username => $username );
    my $challenge = String::Random->new->randregex('[A-Za-z0-9]{32}');
    $c->session->set( challenge => $challenge );
    my @allowCredentials = ();
    my @credentialIds = keys %{$CREDENTIAL_DB};
    foreach my $credentialId(@credentialIds) {
        if($CREDENTIAL_DB->{$credentialId}->{username} eq $username) {
            push(@allowCredentials, {type => 'public-key', id => encode_base64($credentialId)});
        }
    };

    # 1. Let options be a new PublicKeyCredentialRequestOptions structure configured to the Relying Party's needs for the ceremony.
    my $PublicKeyCredentialRequestOptions = {
        challenge        => $challenge,
        rpId => 'localhost',
        allowCredentials => \@allowCredentials,
        userVerification => 'discouraged'
    };
    $c->session->set( PublicKeyCredentialRequestOptions => $PublicKeyCredentialRequestOptions );
    return $c->render(
        'login2.tx',
        {
            PublicKeyCredentialRequestOptions =>
              encode_json($PublicKeyCredentialRequestOptions)
        }
    );
};


post '/login3' => sub {
    my ($c)      = @_;
    my $response = decode_json( $c->req->parameters->{assertion} );
    my $PublicKeyCredentialRequestOptions = $c->session->get( 'PublicKeyCredentialRequestOptions' );

    # 5. If options.allowCredentials is not empty, verify that credential.id identifies one of the public key credentials listed in options.allowCredentials.
    my @allowCredentials = @{$PublicKeyCredentialRequestOptions->{allowCredentials}};
    if(scalar (grep {decode_base64($_->{id}) eq urlsafe_b64decode($response->{id})} @allowCredentials) == 0) {
        die "credential id unmatched.";
    }
    
    # 6. Identify the user being authenticated and verify that this user is the owner of the public key credential source credentialSource identified by credential.id:
    # ↪ If the user was identified before the authentication ceremony was initiated, e.g., via a username or cookie, verify that the identified user is the owner of credentialSource.
    my $username = $c->session->get('username');
    my $credentialOwnerUsername = $CREDENTIAL_DB->{urlsafe_b64decode($response->{id})}->{username};
    if(!($credentialOwnerUsername eq $username)) {
        die "username nmatched. credential owner: $credentialOwnerUsername username:$username.";
    }
    
    # If response.userHandle is present, let userHandle be its value. Verify that userHandle also maps to the same user.
    # TODO userHandle will match user.id for registration.

    # ↪ If the user was not identified before the authentication ceremony was initiated, verify that response.userHandle is present, and that the user identified by this value is the owner of credentialSource.
    # TODO userHandle will match user.id for registration.

    # 7. Using credential.id (or credential.rawId, if base64url encoding is inappropriate for your use case), look up the corresponding credential public key and let credentialPublicKey be that credential public key.
    my $credentialPublicKey = $CREDENTIAL_DB->{urlsafe_b64decode($response->{id})}->{pubKey};

    # 8. Let cData, authData and sig denote the value of response’s clientDataJSON, authenticatorData, and signature respectively.
    my $authData = $response->{response}->{authenticatorData};
    my $sig = $response->{response}->{signature};

    # 9. Let JSONtext be the result of running UTF-8 decode on the value of cData.
    # 10. Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.
    my $cData = decode_json( decode_base64($response->{response}->{clientDataJSON}));

    # 11. Verify that the value of C.type is the string webauthn.get.
    if(!($cData->{type} eq 'webauthn.get')) {
        die $cData->{type} . "is not 'webauthn.get'.";
    }

    # 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
    my $challenge = $c->session->get('challenge');
    if ( !( $cData->{challenge} eq $challenge ) ) {
        die "challenge unmatched.";
    }

    # 13. Verify that the value of C.origin matches the Relying Party's origin.
    if ( !( $cData->{origin} eq 'http://localhost:5000' ) ) {
        die "origin unmatched. C.origin:" . $cData->{origin};
    }

    # 14. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
    use bytes;    
    my $rpIdHash = substr urlsafe_b64decode($authData), 0, 32;
    $rpIdHash =~ s/(.)/sprintf '%02x', ord $1/seg;
    if ( !( $rpIdHash eq sha256_hex('localhost') ) ) {
        $authData =~ s/(.)/sprintf '%02x', ord $1/seg;

        die "rpIdHash unmatched. rpIdHash:"
          . $rpIdHash
          . " expected:"
          . sha256_hex('localhost') . ' authData:' . $authData;
    }

    # 15. Verify that the User Present bit of the flags in authData is set.
    my $flags = unpack( 'C', substr $authData, 32, 1 );
    if ( !( $flags & 1 ) ) {
        # User Present is first bit.
        die "User Present flag is not on.";
    }

    # 16. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
    # if ( !( $flags & 4 ) ) {
    #     # User Verified is third bit.
    #     die "User Present flag is not on.";
    # }
    my $signCount = substr $authData, 33, 4;

    # 17. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
    # TODO

    # 18. Let hash be the result of computing a hash over the cData using SHA-256.
    my $hash = sha256( urlsafe_b64decode( $response->{response}->{clientDataJSON}));

    # 19. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
    # supported only ECC
    # ref. https://github.com/LemonLDAPNG/Authen-WebAuthn/blob/main/lib/Authen/WebAuthn.pm#L478
    my $coseKey = decode_cbor($credentialPublicKey);
    my $curve       = $coseKey->{-1};
    my $x           = $coseKey->{-2};
    my $y           = $coseKey->{-3};
    my $id_to_curve = { 1 => 'secp256r1', };
    my $pk         = Crypt::PK::ECC->new();
    my $curve_name = $id_to_curve->{$curve};
    unless ($curve_name) {
        die "Unsupported curve $curve";
    }
    $pk->import_key( {
            curve_name => $curve_name,
            pub_x      => unpack( "H*", $x ),
            pub_y      => unpack( "H*", $y ),
        }
    );
    unless($pk->verify_message(urlsafe_b64decode($sig), urlsafe_b64decode($authData) . $hash, ("SHA256"))) {
        die "Failed to verify signature."
    }

    return $c->render(
        'login3.tx',
        {
            cred =>
              encode_json($cData->{type})
        }
    );

};

post '/account/logout' => sub {
    my ($c) = @_;
    $c->session->expire();
    return $c->redirect('/');
};

1;
