rule Win_Trojan_Annihilator_4
{
strings:
	$a0 = { 60e80000582d0a01958db62b01e80200eb13b91e018bfeba }


condition:
	$a0
}