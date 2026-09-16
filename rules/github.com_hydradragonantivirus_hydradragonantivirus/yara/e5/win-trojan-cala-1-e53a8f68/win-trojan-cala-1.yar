rule Win_Trojan_CALA_1
{
strings:
	$a0 = { 407402eb26817ebd4e457402eb1d807ef3027402eb15817efb00037302eb0c837ee1007502 }


condition:
	$a0
}