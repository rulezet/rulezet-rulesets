rule Win_Trojan_Omega_5
{
strings:
	$a0 = { 897e2e83ec15b915008bfc8bf5a4e2fde81d00b915 }


condition:
	$a0
}