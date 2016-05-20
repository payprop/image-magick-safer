package Image::Magick::Safer;

=head1 NAME

Image::Magick::Safer - Wrap Image::Magick Read method to check magic bytes

=for html
<a href='https://travis-ci.org/Humanstate/image-magick-safer?branch=master'><img src='https://travis-ci.org/Humanstate/image-magick-safer.svg?branch=master' alt='Build Status' /></a>
<a href='https://coveralls.io/r/Humanstate/image-magick-safer?branch=master'><img src='https://coveralls.io/repos/Humanstate/image-magick-safer/badge.png?branch=master' alt='Coverage Status' /></a>

=head1 VERSION

0.01

=head1 SYNOPSIS

	use Image::Magick::Safer;

	# functions just like Image::Magick but wraps the Read method
	# to check the magic bytes of any images using File::LibMagic
	my $magick = Image::Magick::Safer->new;

	# if any @files have a MIME type that looks quesiontable then
	# $e will be popluated
	if ( my $e = $magick->Read( @files ) ) {
		# bail out, unsafe to continue
		....
	}

=head1 DESCRIPTION

Image::Magick::Safer is a drop in wrapper around Image::Magick, it adds a
magic byte check to the C<Read> method to check the file MIME type using
L<File::LibMagic>. If a file looks questionable then it will preven the file
being passed to the real Image::Magick::Read method and return an error.

You can replace any calls to C<Image::Magick> with C<Image::Magick::Safer>
and the functionality will be retained with the added Read protection.

If you need to override the default MIME types then you can set the modules
C<$Image::Magick::Safer::Unsafe> hash to something else or add extra types:

	# add SVG check to the defaults
	$Image::Magick::Safer::Unsafe->{'image/svg+xml'} = 1;

The default MIME types considered unsafe are as follows:

	text/plain
	application/x-compress
	application/x-compressed
	application/gzip
	application/bzip2
	application/x-bzip2
	application/x-gzip
	application/x-rar
	application/x-z
	application/z

Note that i make B<NO GUARANTEE> that this will fix and/or protect you from
exploits, it's just another safety check. You should update to the latest
version of ImageMagick to protect yourself against potential exploits.

Also note that to install the L<File::LibMagic> module you will need to have
both the library (libmagic.so) and the header file (magic.h). See the perldoc
for L<File::LibMagic> for more information.

=head1 WHY ISN'T THIS A PATCH IN Image::Magick?

Image::Magick moves at a glacial pace, and involves a 14,000 .xs file. No
thanks. This will probably get patched in the next version, so for the time
being this module exists.

=cut

use strict;
use warnings;

use parent 'Image::Magick';
use File::LibMagic;

our $VERSION = '0.01';

# imagemagick can automatically uncompress archive files so there's another
# attack vector in having an exploit image zipped up, so just checking for
# text/plain isn't enough
$Image::Magick::Safer::Unsafe = {
	map { $_ => 1 }
		'text/plain',
		'application/x-compress',
		'application/x-compressed',
		'application/gzip',
		'application/bzip2',
		'application/x-bzip2',
		'application/x-gzip',
		'application/x-rar',
		'application/x-z',
		'application/z',
};

my $magic;

sub Read {
	my ( $self,@images ) = @_;

	$magic ||= File::LibMagic->new;

	foreach my $image ( @images ) {

		# info has:
		#     mime_with_encoding
		#     description
		#     encoding
		#     mime_type
		if ( my $info = $magic->info_from_filename( $image ) ) {

			# if the mime_type is within the $Image::Magick::Safer::Unsafe
			# hash or we can't figure it out then we assume it's not a real
			# image and therefore could have an exploit within the file
			if (
				! $info->{mime_type}
				|| $Image::Magick::Safer::Unsafe->{ $info->{mime_type} }
			) {
				return "$image is of type @{[ $info->{mime_type} ]}, potentially unsafe";
			}
		} else {
			return "unable to establish mime_type for $image";
		}
	}

	# all images *seem* ok, delegate to the real Image::Magick
	return $self->SUPER::Read( @images );
}

=head1 SEE ALSO

L<Image::Magick> - the library this module wraps

L<https://www.imagemagick.org> - ImageMagick

L<https://imagetragick.com/> - ImageMagick exploits

=head1 AUTHOR

Lee Johnson - C<leejo@cpan.org>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself. If you would like to contribute documentation,
features, bug fixes, or anything else then please raise an issue / pull request:

    https://github.com/Humanstate/image-magick-safer

=cut

1;
