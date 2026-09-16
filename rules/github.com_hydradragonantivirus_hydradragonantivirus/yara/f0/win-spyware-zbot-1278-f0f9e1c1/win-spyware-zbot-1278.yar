rule Win_Spyware_Zbot_1278
{
strings:
	$a0 = { 58ffd039c075??c2 }


condition:
	$a0
}