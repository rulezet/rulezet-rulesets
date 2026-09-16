rule Win_Trojan_Joan_1
{
strings:
	$a0 = { 505156571e06e800005e83ee0a0e1f33ff8b84b4018945068b84b6018945108ec726803efa04ea744db8fa04268706 }


condition:
	$a0
}