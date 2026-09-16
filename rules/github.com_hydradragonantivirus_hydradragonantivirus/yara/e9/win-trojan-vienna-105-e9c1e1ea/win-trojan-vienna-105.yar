rule Win_Trojan_Vienna_105
{
strings:
	$a0 = { ed30018db6f102bf0001b90300fcf3a406b42fcd2189 }


condition:
	$a0
}