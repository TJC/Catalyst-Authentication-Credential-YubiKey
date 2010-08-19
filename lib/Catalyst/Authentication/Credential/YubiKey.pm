package Catalyst::Authentication::Credential::YubiKey;
use strict;
use warnings;
use Catalyst::Exception;
use Auth::Yubikey_WebClient;
use parent qw(Class::Accessor::Fast);

=head1 NAME

Catalyst::Authentication::Credential::YubiKey - YubiKey authentication

=head1 VERSION

Version 0.02

=head1 SYNOPSIS

Authenticate Catalyst apps with Yubico's YubiKey system.

Uses the Catalyst::Plugin::Authentication system.

  use Catalyst qw(
    ...
    Authentication
    ...
  );

  __PACKAGE__->config(
    'Plugin::Authentication' => {
      default => {
        credential => {
          class => 'YubiKey',

          # This is your API ID, from http://yubico.com/developers/api/
          api_id => 666,

          # This is your API Key, as above:
          api_key => 'aaaaaaad34db33fzzzzzzzzzz/abc=',

          # This is the column in your store that contains the yubikey ID,
          # for mapping that ID to username or whatever.
          # It defaults to 'id' if not specified.
          id_for_store => 'id',
        },
        ...
      },
    },
  );

=head1 TODO

I am currently using Auth::Yubikey_WebClient as the underlying library for
querying Yubico's webservice. However it would be nice if that library was
improved to return more of the details, rather than just 'OK'.

Also would be good to support in-house authentication servers. (Since Yubico
have open-sourced theirs, and some people may be using such.)

=head1 METHODS

=cut

our $VERSION = '0.02';

__PACKAGE__->mk_accessors(qw(api_id api_key realm id_for_store));

=head2 new

Standard constructor following the Catalyst::Authentication::Credential
model.

=cut

sub new {
    my ($class, $config, $app, $realm) = @_;
    my $self = {};
    bless $self, $class;

    $self->api_id($config->{api_id});
    $self->api_key($config->{api_key});
    # $self->realm($realm);
    $self->id_for_store($config->{id_for_store} || 'id');

    unless ($self->api_id and $self->api_key) {
        Catalyst::Exception->throw(
            __PACKAGE__ . " missing api_id and api_key"
        );
    }

    return $self;
}

=head2 authenticate

Standard authentication method, as per Cat-Auth-Credential standard.

=cut

sub authenticate {
    my ($self, $c, $realm, $authinfo) = @_;
    my $otp = $authinfo->{otp};

    my $result = Auth::Yubikey_WebClient::yubikey_webclient(
        $otp, $self->api_id, $self->api_key
    );
    unless ($result eq 'OK') {
        $c->log->error("User auth failed: $result");
        return;
    }

    # The user ID seems to be the first 12 characters..
    my $yubi_id = substr($otp, 0, 12);
    my $user = $realm->find_user({ $self->id_for_store => $yubi_id });
    unless ($user) {
        $c->log->error("Authenticated user, but could not locate in "
            ." our Store!");
        return;
    }
    return $user;
}

=head1 AUTHOR

Toby Corkindale, C<< <tjc at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-catalyst-authentication-credential-yubikey at rt.cpan.org>, or through
the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Catalyst-Authentication-Credential-YubiKey>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Catalyst::Authentication::Credential::YubiKey

You can also look for information at:
http://github.com/TJC/Catalyst-Authentication-Credential-YubiKey

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Catalyst-Authentication-Credential-YubiKey>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Catalyst-Authentication-Credential-YubiKey>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Catalyst-Authentication-Credential-YubiKey>

=item * Search CPAN

L<http://search.cpan.org/dist/Catalyst-Authentication-Credential-YubiKey/>

=back

=head1 COPYRIGHT & LICENSE

Copyright 2010 Toby Corkindale, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
