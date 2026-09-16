rule OpenSSL_dh512_p__8_byt_64_
{
strings:
	$a0 = { da583c16d9852289d0e4af756f4cca92dd4be533b804fb0fed94ef9c8a4403ed574650d36999db29d776276ba2d3d412e218f4dd1e084cf6d8003e7c4774e833 }

condition:
	$a0
}