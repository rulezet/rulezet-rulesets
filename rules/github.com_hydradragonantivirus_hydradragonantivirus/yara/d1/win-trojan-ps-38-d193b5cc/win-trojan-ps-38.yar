rule Win_Trojan_PS_38
{
strings:
	$a0 = { 89162e02a32c025bb91a0051b92602b440ba0000cd2133d233c9b80042cd2159b440ba2a02 }


condition:
	$a0
}