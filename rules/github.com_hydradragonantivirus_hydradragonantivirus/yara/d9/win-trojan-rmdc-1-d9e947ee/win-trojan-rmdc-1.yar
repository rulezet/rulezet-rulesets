rule Win_Trojan_Rmdc_1
{
strings:
	$a0 = { fc3b74e580fc4b757d0e1fb860022ea34f021fb80043cd }


condition:
	$a0
}