rule Win_Trojan_Mini_40
{
strings:
	$a0 = { 8bec8b6e0081ed0601e8e1008db60102bf000157fca5a4b41a8d960d02cd21b44eb905008db60402fce89e002b }


condition:
	$a0
}