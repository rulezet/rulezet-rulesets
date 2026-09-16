rule Win_Trojan_Fayte_2
{
strings:
	$a0 = { 9c1b01464686fb81fe7e0175f2803e0401000f85d7 }


condition:
	$a0
}