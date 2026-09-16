rule Win_Trojan_Agent_33952
{
strings:
	$a0 = { 51585850535868bf2041009797545857 }


condition:
	$a0
}