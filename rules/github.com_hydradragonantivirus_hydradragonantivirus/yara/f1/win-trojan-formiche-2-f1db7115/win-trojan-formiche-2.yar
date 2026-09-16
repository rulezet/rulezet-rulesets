rule Win_Trojan_Formiche_2
{
strings:
	$a0 = { aa552ec40637018ccacf }


condition:
	$a0
}