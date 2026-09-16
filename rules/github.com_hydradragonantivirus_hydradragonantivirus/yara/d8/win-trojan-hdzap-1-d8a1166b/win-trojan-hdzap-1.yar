rule Win_Trojan_HDZap_1
{
strings:
	$a0 = { 6c041f3cc077103c807219ba7000b012ee42b000eeebfeb88003b90100ba8000cd13ebe7e9 }


condition:
	$a0
}