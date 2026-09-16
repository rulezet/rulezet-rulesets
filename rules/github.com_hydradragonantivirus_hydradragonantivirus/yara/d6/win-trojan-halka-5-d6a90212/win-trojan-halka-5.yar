rule Win_Trojan_Halka_5
{
strings:
	$a0 = { 8bfc368b2d81ed0d0183c402b98c028db638018bfeac2e2a060401eb04b44ccd2150b80054 }


condition:
	$a0
}