rule Win_Trojan_Delf_2253
{
strings:
	$a0 = { 558becb91f0000006a006a004975f9b828 }

	$a1 = { 566932676852384d546d667667507374 }


condition:
	$a0 and $a1
}