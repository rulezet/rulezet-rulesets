rule Win_Trojan_ID_2
{
strings:
	$a0 = { f80090b440cd212bf7897501c605e9c74503494433c933d2b80042cd21ba0300b105b440cd21 }


condition:
	$a0
}