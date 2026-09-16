rule Win_Trojan_Lisa_3
{
strings:
	$a0 = { 4233c933d2cd21b4408d966b02b90300cd21b8024233c933d2cd21b4408d960301b94200cd21 }


condition:
	$a0
}