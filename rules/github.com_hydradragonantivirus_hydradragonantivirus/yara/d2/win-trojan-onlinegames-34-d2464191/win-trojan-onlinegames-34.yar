rule Win_Trojan_Onlinegames_34
{
strings:
	$a0 = { c6e8401a000028139f8f55eff06bae44614f45e12264159231052d0f712c258cb0d33d09f0fa358637 }


condition:
	$a0
}