rule Win_Trojan_O_2
{
strings:
	$a0 = { 012ec6069b0200b82435cd212e891eb5022e8c06b702b425bafe01cd210e07ba5702e80f00e87000b82425bab502 }


condition:
	$a0
}