rule Win_Trojan_Beer_21
{
strings:
	$a0 = { 5351509cbb????b92e082bcb2ea0????2e300743e2fa9d58595bc3 }


condition:
	$a0
}