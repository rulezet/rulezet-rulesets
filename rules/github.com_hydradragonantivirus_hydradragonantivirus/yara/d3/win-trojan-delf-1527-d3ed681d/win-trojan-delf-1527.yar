rule Win_Trojan_Delf_1527
{
strings:
	$a0 = { 64ff306489206a01e862d1ffff6a01e85bd1ffff6a01e854d1ffff6a01e84dd1ffff6a01e846d1ffff6a01e83fd1ffff6a01e838d1ffff6a01e831d1ffff6a01e82ad1ffff6a01e823d1ffff6a01e81cd1ffff6a01 }


condition:
	$a0
}