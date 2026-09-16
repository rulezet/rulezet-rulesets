rule Win_Trojan_DigitalF_1
{
strings:
	$a0 = { 616b249090b98000be8000bf7ffff3a4b8b802 }


condition:
	$a0
}