package amon::webauthn::Web::Dispatcher;
use strict;
use warnings;
use utf8;
use String::Random;
use JSON;
use Amon2::Web::Dispatcher::RouterBoom;

any '/' => sub {
    my ($c) = @_;
    return $c->render('index.tx');
};

any '/register1' => sub {
    my ($c) = @_;
    return $c->render('register1.tx');
};

post '/register2' => sub {
    my ($c) = @_;
    my $username = $c->req->parameters->{username};
    my $userId = String::Random->new->randregex('[A-Za-z0-9]{32}');
    my $challenge = String::Random->new->randregex('[A-Za-z0-9]{32}');
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
    my $cred = $c->req->parameters->{cred};
    print $cred;
    return $c->render('index.tx');
};

post '/account/logout' => sub {
    my ($c) = @_;
    $c->session->expire();
    return $c->redirect('/');
};

1;
