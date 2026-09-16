rule Win_Trojan_LightGeneral_4
{
strings:
	$a0 = { 1800b440baa505cd21b80157268b4d0d268b550fcd21b43ecd21c3ba0001b9bd04b440cd21 }


condition:
	$a0
}