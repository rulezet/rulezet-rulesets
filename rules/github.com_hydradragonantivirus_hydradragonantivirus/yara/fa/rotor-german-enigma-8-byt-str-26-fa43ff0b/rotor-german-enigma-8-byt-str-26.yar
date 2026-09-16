rule _rotor_German_Enigma__8_byt_STR_26_
{
strings:
	$a0 = { 5952554851534c4450584e474f4b4d494542465a4357564a4154 }

condition:
	$a0
}