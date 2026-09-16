rule Win_Trojan_Small_4384
{
strings:
	$a0 = { b800004000[0-255]81e8891a????0589362726535e01c6 }


condition:
	$a0
}