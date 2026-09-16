rule Win_Trojan_Mini_53
{
strings:
	$a0 = { 0202b80057cd215152b04033d2b90002e82affb000e8d400b040baff01b90400e81aff5a59 }


condition:
	$a0
}