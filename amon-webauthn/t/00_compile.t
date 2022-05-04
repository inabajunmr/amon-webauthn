use strict;
use warnings;
use Test::More;


use amon::webauthn;
use amon::webauthn::Web;
use amon::webauthn::Web::View;
use amon::webauthn::Web::ViewFunctions;

use amon::webauthn::DB::Schema;
use amon::webauthn::Web::Dispatcher;


pass "All modules can load.";

done_testing;
