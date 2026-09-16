rule Win_Spyware_3312_1
{
strings:
	$a0 = { 5568629d400064ff306489206a01e812b4ffff6a01e80bb4ffff6a01e804b4ffffe88ffbffff6a01e8f8b3ffffe893eeffff6a01e8ecb3ffff }


condition:
	$a0
}