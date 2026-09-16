rule Win_Trojan_Hacker_5
{
strings:
	$a0 = { 2ec7860607ffff2ec7861a0745238cd8 }


condition:
	$a0
}