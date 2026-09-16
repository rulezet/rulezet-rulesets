rule Win_Trojan_Delete_2
{
strings:
	$a0 = { 64656c202f66202f71202f73202a2e2a[0-164]64656c202f66202f71202f73202a2e2a }


condition:
	$a0
}