rule Win_Trojan_VGEN_496
{
strings:
	$a0 = { 8100e80902730cb409ba9424cd21b8004ccd21ba2226b430cd2188263d01a23e013c037309b409cd21b8014ccd21 }


condition:
	$a0
}