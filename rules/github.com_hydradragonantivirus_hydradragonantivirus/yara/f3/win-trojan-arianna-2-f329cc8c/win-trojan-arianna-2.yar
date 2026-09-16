rule Win_Trojan_Arianna_2
{
strings:
	$a0 = { fc368a45d4284600804600f24978064d4e79eaebe5 }


condition:
	$a0
}