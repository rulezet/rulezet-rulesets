rule Win_Trojan_Vienna_96
{
strings:
	$a0 = { 81ed48018db64603bf0001b90300fcf3a406b42fcd2189 }


condition:
	$a0
}