rule Win_Trojan_Tver_1
{
strings:
	$a0 = { 1e06169c3d004b7403e98100b43db002cd217303eb7790 }


condition:
	$a0
}