rule Win_Trojan_Annihilator_3
{
strings:
	$a0 = { e80000582d0a01958db62b01e80200eb13b91c018bfeba }


condition:
	$a0
}