rule Win_Trojan_Delf_2261
{
strings:
	$a0 = { 558becb90e0000006a006a004975f95356b880f540 }

	$a1 = { 4578706c4f7265722e657865 }


condition:
	$a0 and $a1
}