rule Win_Trojan_Anti_20
{
strings:
	$a0 = { be00015a58ffe650b40e8ad0cd2158 }


condition:
	$a0
}