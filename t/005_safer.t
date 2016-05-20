#!perl

# mocking Image::Magick dependency here for testing as it may not be installed
# and it's an absolute swine to install so that's not going to work on
# cpantesters et al
BEGIN {
    $INC{'Image/Magick.pm'} ||= "mocked";
};

package Image::Magick;

sub new { bless( {},shift ); };

1;

use strict;
use warnings;

use Test::More;
use FindBin qw/ $Bin /;
use File::Spec::Functions qw/ catdir /;
use File::Basename;

use Image::Magick::Safer;

my $magick = Image::Magick::Safer->new;

# Image::Magick::Read could fail for other reasons, so we monkey patch it here
# to make sure it returns "success" (which in Image::Magick terms is void)
no warnings 'redefine';
no warnings 'once';
*Image::Magick::Read = sub ($;@) {};

# add SVG check to the defaults
$Image::Magick::Safer::Unsafe->{'image/svg+xml'} = 1;

foreach my $file ( glob catdir( $Bin,"exploit","*" ) ) {

	foreach my $method ( qw/ Read ReadImage read readimage / ) {
		my $e = $magick->$method( $file );
		like(
			$e,
			qr/potentially unsafe|unable to establish/,
			"$method exception with exploitable @{[ basename $file ]}"
		);
	}
}

foreach my $file ( glob catdir( $Bin,"genuine","*" ) ) {

	foreach my $method ( qw/ Read ReadImage read readimage / ) {
		ok(
			! $magick->$method( $file ),
			"No $method exception with safe @{[ basename $file ]}"
		);
	}
}

done_testing();
