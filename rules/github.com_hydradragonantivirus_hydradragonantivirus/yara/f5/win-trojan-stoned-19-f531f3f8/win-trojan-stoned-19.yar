rule Win_Trojan_Stoned_19
{
strings:
	$a0 = { 40008ed8a1130048a3130033db531fb106d3e08ec033c0 }


condition:
	$a0
}