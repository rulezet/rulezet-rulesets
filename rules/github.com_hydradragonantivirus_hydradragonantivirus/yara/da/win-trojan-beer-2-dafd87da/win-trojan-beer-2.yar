rule Win_Trojan_Beer_2
{
strings:
	$a0 = { 02b93f0b2bcb2ea0de012e300743e2fa9d58595bc3e8e2ffb440b93f0bba03012bca8b1e580b }


condition:
	$a0
}