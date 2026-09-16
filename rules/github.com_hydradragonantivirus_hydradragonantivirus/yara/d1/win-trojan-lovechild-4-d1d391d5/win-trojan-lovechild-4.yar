rule Win_Trojan_LoveChild_4
{
strings:
	$a0 = { 0100ba80038bd9b81003cd13fece79 }


condition:
	$a0
}