rule Win_Trojan_SillyC_42
{
strings:
	$a0 = { e9742b33c9b8024299cd212d0300898485008bd6b98d00b440cd2133c9b8004299cd21b4 }


condition:
	$a0
}