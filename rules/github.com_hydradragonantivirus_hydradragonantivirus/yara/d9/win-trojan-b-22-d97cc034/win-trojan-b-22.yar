rule Win_Trojan_B_22
{
strings:
	$a0 = { cb2ea0dd012e300743e2fa9d58595bc3e8e2ffb440b91f0fba03012bca8b1e380fe84601 }


condition:
	$a0
}