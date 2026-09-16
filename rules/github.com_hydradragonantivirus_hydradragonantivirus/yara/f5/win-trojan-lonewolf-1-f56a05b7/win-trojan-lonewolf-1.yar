rule Win_Trojan_LoneWolf_1
{
strings:
	$a0 = { 90cd201a1ae800005e81ee0e01e80500e98500000050535152b994018bee81c66c048bfefdad33861901ab }


condition:
	$a0
}