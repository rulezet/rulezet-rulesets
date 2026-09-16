rule Win_Trojan_SillyC_51
{
strings:
	$a0 = { b440ba0001bf9a008b0d81c19f0181e90001cd21b43ecd218cd08ed88ec050ba8000b41acd21 }


condition:
	$a0
}