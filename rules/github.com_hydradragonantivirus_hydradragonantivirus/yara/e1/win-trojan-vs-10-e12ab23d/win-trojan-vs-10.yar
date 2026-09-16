rule Win_Trojan_VS_10
{
strings:
	$a0 = { 01b96d0290b440cd217303eb1c90b90000ba0000b80042cd217303eb0c908d164003b90300 }


condition:
	$a0
}