rule Win_Trojan_VRN_2
{
strings:
	$a0 = { 307504b9b0becf9380ff11742680ff12742180ff4e74 }


condition:
	$a0
}