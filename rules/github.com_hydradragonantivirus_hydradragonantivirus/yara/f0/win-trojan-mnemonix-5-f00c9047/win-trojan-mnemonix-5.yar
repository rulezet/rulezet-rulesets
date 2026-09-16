rule Win_Trojan_Mnemonix_5
{
strings:
	$a0 = { ca01bb1f013402e6212e8137000043433402e621e2ef }


condition:
	$a0
}