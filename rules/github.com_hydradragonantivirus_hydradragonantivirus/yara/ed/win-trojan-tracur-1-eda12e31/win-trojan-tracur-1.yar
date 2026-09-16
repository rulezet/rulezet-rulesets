rule Win_Trojan_Tracur_1
{
strings:
	$a0 = { 8b002bcd8345e8042bff81c7add96e8c3345f4ff45f450894dcf8b45ec8f008345ec0456e8a0fbffff83c404836df8040f85c7ffffff }


condition:
	$a0
}