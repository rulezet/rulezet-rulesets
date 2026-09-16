rule Win_Trojan_Bugger_1
{
strings:
	$a0 = { b96803b440cc33c981efff008bd7b80042ccba7203b90200b440cce85100b43eccba7b03e8 }


condition:
	$a0
}