rule Win_Trojan_Vote_3
{
strings:
	$a0 = { 56013d03007534e856013d0b00752cba6f01b44eb92700cd21721bb42fcd218d571eb441cd21 }


condition:
	$a0
}