rule Win_Adware_Goldencasino_1
{
strings:
	$a0 = { 72795f6b65793d22536f6674776172655c5c56546563686e6f6c6f67795c5c476f6c64656e22 }


condition:
	$a0
}