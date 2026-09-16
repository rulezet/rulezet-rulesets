rule Win_Spyware_WOW_24
{
strings:
	$a0 = { f5a7ec3e2f678dc4dc40cc636bc8340ecc89f12d3cbe084c9e15817e0b3e0ab2f2df3adb524ba62a351fefd09ebce208a3476fa9611b922f92857e91063dadd5af0a47e3 }


condition:
	$a0
}