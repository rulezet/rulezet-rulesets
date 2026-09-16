rule Win_Trojan_V_93
{
strings:
	$a0 = { b4408b5e040e1fba7803cd21730ab43ecd21b8fdffeb5490b4408b4e0e8e5e0c8b560acd2172e7 }


condition:
	$a0
}