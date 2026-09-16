rule Win_Trojan_Zbot_1232
{
strings:
	$a0 = { 558becb9050000006a006a004975f9535657b804 }

	$a1 = { 392c682c7740 }


condition:
	$a0 and $a1
}