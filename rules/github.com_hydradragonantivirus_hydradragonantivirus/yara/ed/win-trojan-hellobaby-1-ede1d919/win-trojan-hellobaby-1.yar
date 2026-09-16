rule Win_Trojan_HelloBaby_1
{
strings:
	$a0 = { 25b01cbac103cd21b021bae603cd215a1f078cd82e0306 }


condition:
	$a0
}