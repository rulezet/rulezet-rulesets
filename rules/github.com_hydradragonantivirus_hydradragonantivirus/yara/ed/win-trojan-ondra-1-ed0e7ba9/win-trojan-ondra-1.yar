rule Win_Trojan_Ondra_1
{
strings:
	$a0 = { 4e0089ec5dc20800032a2e2a015c0b26266f6e6472612e }


condition:
	$a0
}