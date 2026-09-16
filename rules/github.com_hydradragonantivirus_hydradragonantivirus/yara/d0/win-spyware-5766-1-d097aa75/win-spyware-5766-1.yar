rule Win_Spyware_5766_1
{
strings:
	$a0 = { 68cc7d40008d55f033c0e848aeffffff75f068cc7d400068d87d400068e87d4000ff75fc68f87d40008d55ec8b45f8e8abf2ffff }


condition:
	$a0
}