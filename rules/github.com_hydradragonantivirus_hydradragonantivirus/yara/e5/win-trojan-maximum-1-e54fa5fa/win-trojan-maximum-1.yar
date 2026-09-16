rule Win_Trojan_Maximum_1
{
strings:
	$a0 = { 08018bdf8db70a018dbfb805b90600ac3434aae2fa8db7f0018dbfbe05b92a00ac3434aae2fa8bfb8bdf8e062c00 }


condition:
	$a0
}