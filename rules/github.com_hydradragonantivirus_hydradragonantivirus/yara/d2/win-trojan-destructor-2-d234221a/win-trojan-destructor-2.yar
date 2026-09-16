rule Win_Trojan_Destructor_2
{
strings:
	$a0 = { fbcb3d004b741980fc3d740f80fc }


condition:
	$a0
}