rule Win_Trojan_Maverick_1
{
strings:
	$a0 = { 96f02895292c777f986cc4422cc714bc77751ee5c71f92fc2893f828322b8989953c2cdbdd072ae8 }


condition:
	$a0
}