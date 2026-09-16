rule Win_Trojan_Trivial_518
{
strings:
	$a0 = { 32d2be0003cd21b44eb92000ba5201cd21813e9e00434f7418b8023dba9e00cd21720e93b440ba0001b15bcd21 }


condition:
	$a0
}