rule Win_Trojan_Gosia_2
{
strings:
	$a0 = { 81c64401b90300bf0001fcf3a45e8bd6 }


condition:
	$a0
}