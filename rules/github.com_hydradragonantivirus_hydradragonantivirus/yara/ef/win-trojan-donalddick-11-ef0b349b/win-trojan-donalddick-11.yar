rule Win_Trojan_DonaldDick_11
{
strings:
	$a0 = { 2e5189d95088d6c1e20888f2c1e20888f2e85b }

	$a1 = { 6f6c6570726f632e65786500706e706d67722e }


condition:
	$a0 and $a1
}