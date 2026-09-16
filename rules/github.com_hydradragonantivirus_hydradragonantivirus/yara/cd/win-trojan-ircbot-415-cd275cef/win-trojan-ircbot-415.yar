rule Win_Trojan_IRCBot_415
{
strings:
	$a0 = { 680002000068ece5400068bce540008d8ddcfaffff681ce3400051e807002f7c }


condition:
	$a0
}