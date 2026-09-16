rule Win_Trojan_B_15
{
strings:
	$a0 = { 4b7403e9db02505351521e0656572e89164e012e8c1e }


condition:
	$a0
}