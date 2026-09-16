rule Win_Trojan_Keybug_1
{
strings:
	$a0 = { 068cc88ed88ec0be16018bfeb9be03ac34ffaae2faf8e014996fab979adfbd939e9c94dfb29e98 }


condition:
	$a0
}