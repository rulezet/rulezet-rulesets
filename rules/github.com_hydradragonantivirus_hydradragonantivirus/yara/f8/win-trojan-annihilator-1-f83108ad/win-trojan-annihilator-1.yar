rule Win_Trojan_Annihilator_1
{
strings:
	$a0 = { 60e80000582d8b01958db6ac01e80200eb13b917018bfeba }


condition:
	$a0
}