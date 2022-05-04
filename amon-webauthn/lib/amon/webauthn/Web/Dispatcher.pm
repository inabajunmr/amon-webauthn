package amon::webauthn::Web::Dispatcher;
use strict;
use warnings;
use utf8;
use String::Random;
use JSON;
use MIME::Base64;
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
    my $origin = $c->session->get('origin');
    if(!($cdata->{origin} eq 'localhost')) {
        die "origin unmatched.";
    }

    # 10. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
    if(defined($cdata->{tokenBinding})) {
        my $tokenBindingStatus = $cdata->{tokenBinding}->{status};
        # verify token binding
    }



    return $c->render('register3.tx', {
        cred => encode_json($response)
    });
};

post '/account/logout' => sub {
    my ($c) = @_;
    $c->session->expire();
    return $c->redirect('/');
};

1;
