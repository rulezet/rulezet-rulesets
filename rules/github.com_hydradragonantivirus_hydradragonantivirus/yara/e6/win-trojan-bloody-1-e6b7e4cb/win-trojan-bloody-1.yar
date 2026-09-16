rule Win_Trojan_Bloody_1
{
strings:
	$a0 = { 37557b7878736e36375d62793937233b }


condition:
	$a0
}