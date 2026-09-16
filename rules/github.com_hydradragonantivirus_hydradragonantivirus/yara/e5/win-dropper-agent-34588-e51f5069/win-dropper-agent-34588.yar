rule Win_Dropper_Agent_34588
{
strings:
	$a0 = { 558bec83ec548d45e450e8010100008bca8d0520704c0cc1e10bbb00600b0c2b }


condition:
	$a0
}