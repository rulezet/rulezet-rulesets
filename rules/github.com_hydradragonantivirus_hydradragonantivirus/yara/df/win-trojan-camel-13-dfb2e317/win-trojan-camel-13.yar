rule Win_Trojan_Camel_13
{
strings:
	$a0 = { e800005d81ed????8d86????ffd0 }

	$a1 = { 8db6????8bfeb9a400ad7304abe2fac3 }


condition:
	$a0 and $a1
}