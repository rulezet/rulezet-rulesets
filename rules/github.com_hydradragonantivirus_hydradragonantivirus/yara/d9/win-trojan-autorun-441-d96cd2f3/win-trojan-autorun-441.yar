rule Win_Trojan_Autorun_441
{
strings:
	$a0 = { 5083d0??5183f9 }


condition:
	$a0
}