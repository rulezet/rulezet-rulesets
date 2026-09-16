rule Win_Trojan_LittlePieces_1
{
strings:
	$a0 = { b82135cd212bdb2681bf03005633 }


condition:
	$a0
}