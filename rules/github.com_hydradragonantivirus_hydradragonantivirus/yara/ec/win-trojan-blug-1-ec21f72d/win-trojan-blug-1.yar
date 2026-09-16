rule Win_Trojan_Blug_1
{
strings:
	$a0 = { 2a2e657865[0-1]63616c632e657865 }

	$a1 = { 4b6f526e }

	$a2 = { 426c61636b425547206279206f7063306465 }


condition:
	$a0 and $a1 and $a2
}