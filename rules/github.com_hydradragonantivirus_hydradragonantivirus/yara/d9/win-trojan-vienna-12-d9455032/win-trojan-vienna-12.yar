rule Win_Trojan_Vienna_12
{
strings:
	$a0 = { 8bf283c60a90bf0001b903 }


condition:
	$a0
}