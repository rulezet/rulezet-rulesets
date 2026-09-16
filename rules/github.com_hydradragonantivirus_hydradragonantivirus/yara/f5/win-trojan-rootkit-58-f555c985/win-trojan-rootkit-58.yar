rule Win_Trojan_Rootkit_58
{
strings:
	$a0 = { 83ec1456578b3d0820001068003000108d442410 }


condition:
	$a0
}