rule Win_Trojan_Runtime_1
{
strings:
	$a0 = { 90b90300b440cd21b8024233c933d2cd218bd681ea }


condition:
	$a0
}