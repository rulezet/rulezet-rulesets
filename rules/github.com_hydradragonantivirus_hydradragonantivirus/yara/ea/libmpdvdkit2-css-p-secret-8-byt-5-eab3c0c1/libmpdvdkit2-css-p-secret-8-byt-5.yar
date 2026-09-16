rule libmpdvdkit2_css_p_secret__8_byt_5_
{
strings:
	$a0 = { 55d6c4c528 }

condition:
	$a0
}