rule Win_Trojan_Cannabis_6
{
strings:
	$a0 = { 10008ed8a113034848a313031fb106d3e02dc0078ec0b9 }


condition:
	$a0
}