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

# key is credential id.
our $CREDENTIAL_DB = {};

# our %CREDENTIAL_DB;

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
        attestation => 'direct'
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
    if ( !( $flags & 4 ) ) {

        # User Verified is third bit.
        die "User Present flag is not on.";
    }
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
    $c->session->set( userId => $username );
    my $challenge = String::Random->new->randregex('[A-Za-z0-9]{32}');
    $c->session->set( challenge => $challenge );
    my @allowCredentials = ();
    my @credentialIds = keys %{$CREDENTIAL_DB};
    foreach my $credentialId(@credentialIds) {
        if($CREDENTIAL_DB->{$credentialId}->{username} eq $username) {
            push(@allowCredentials, {type => 'public-key', id => encode_base64($credentialId)});
        }
    };
    my $PublicKeyCredentialRequestOptions = {
        challenge        => $challenge,
        rpId => 'localhost',
        allowCredentials => \@allowCredentials,
        userVerification => 'preferred'
    };
    return $c->render(
        'login2.tx',
        {
            PublicKeyCredentialRequestOptions =>
              encode_json($PublicKeyCredentialRequestOptions)
        }
    );    
};

post '/account/logout' => sub {
    my ($c) = @_;
    $c->session->expire();
    return $c->redirect('/');
};

1;
