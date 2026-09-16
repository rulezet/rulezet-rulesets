rule Win_Trojan_Vundo_31
{
strings:
	$a0 = { 60e8db180000185e43030000fad65343190000064fb3d41d00006019de70 }


condition:
	$a0
}