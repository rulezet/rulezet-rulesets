rule Win_Trojan_Zany_12
{
strings:
	$a0 = { 8bd6b99802b440cd217303eb76902bc92bd2b80042cd218d940800b90300b43fcd217303eb }


condition:
	$a0
}