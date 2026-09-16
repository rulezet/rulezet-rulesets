rule Win_Trojan_EE_1
{
strings:
	$a0 = { 31c08ed089dc8ed889c7a113042d020090b106a313 }


condition:
	$a0
}