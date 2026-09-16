rule Win_Trojan_Punisher_2
{
strings:
	$a0 = { e800005e83ee048dbc22008d9c5b062e8b945e06d0c2d0ce2e31174bfa3bdf73f3 }


condition:
	$a0
}