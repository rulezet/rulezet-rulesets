rule Win_Trojan_Vlad_2
{
strings:
	$a0 = { 04e80300eb1190be2d0003f28bfeb9f502313c46e2fbc3 }


condition:
	$a0
}