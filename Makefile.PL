use inc::Module::Install;

name     'Catalyst-Authentication-Credential-YubiKey';
all_from 'lib/Catalyst/Authentication/Credential/YubiKey.pm';
author   'Toby Corkindale <tjc@cpan.org>';
license  'perl';

requires 'Catalyst::Exception';
requires 'parent';
requires 'Auth::Yubikey_WebClient' => 2.00;

build_requires 'Test::More';

auto_install;

WriteAll;

