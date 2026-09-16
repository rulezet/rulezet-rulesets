rule Win_Trojan_Tufik_5
{
strings:
	$a0 = { e8000000005b81eb943a4000ff3424e8bffeffff0bc07505e9c90b0000 }


condition:
	$a0
}