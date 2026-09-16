rule Win_Trojan_Beer_12
{
strings:
	$a0 = { b97b0d2bcb2ea0de012e300743e2fa9d58595bc3e8e2ffb440b97b0dba03012bca8b1e940d }


condition:
	$a0
}