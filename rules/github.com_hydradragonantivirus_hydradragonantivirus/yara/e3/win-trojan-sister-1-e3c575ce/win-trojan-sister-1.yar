rule Win_Trojan_Sister_1
{
strings:
	$a0 = { b8024233c999cd2150f7d8250f00917412b440cd21730ce9ab00b43ecd21b44fe929ff5803 }


condition:
	$a0
}