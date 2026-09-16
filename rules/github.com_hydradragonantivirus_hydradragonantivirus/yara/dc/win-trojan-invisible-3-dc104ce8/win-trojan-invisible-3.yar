rule Win_Trojan_Invisible_3
{
strings:
	$a0 = { 0e7200555df5f5b9ea02ba0e3f7c007f0081c134082c009c9deb003097eef2515950584300f27b000400e2ef }


condition:
	$a0
}