rule Win_Trojan_Vacsina_2
{
strings:
	$a0 = { 8ed88ec08ed083c402b80000502e }


condition:
	$a0
}