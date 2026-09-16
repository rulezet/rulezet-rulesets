rule Win_Trojan_Quicker_1
{
strings:
	$a0 = { 7b202e6563686f202d61202a2a2a20706f727420313133[0-60]2e6f70656e[0-16]2d656c2040666c6f6f64 }


condition:
	$a0
}