rule Win_Trojan_Philis_93
{
strings:
	$a0 = { 57568bf75e565783c4045683c4045f57bf407098 }


condition:
	$a0
}