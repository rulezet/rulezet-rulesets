rule Win_Trojan_Burma_2
{
strings:
	$a0 = { f900e8ce00e8d300e8f000e81401e8ca00e81901e8 }


condition:
	$a0
}