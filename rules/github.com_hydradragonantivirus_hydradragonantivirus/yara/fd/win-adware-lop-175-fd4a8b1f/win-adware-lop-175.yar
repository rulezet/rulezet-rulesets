rule Win_Adware_Lop_175
{
strings:
	$a0 = { 441b6737636af99b236853d38831f716f9b3a4dbed8a4aa66938d55c8b351ae62b6786b4e299d4e90571ff99be759ee132f1bf1257bd613bed50abab }


condition:
	$a0
}