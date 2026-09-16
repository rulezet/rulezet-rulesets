rule Win_Trojan_Gen_104
{
strings:
	$a0 = { ed31b8f130cd218cdb3c0272464b8e }


condition:
	$a0
}