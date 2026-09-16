rule Win_Trojan_Abraxas_3
{
strings:
	$a0 = { b43c33c9ba9e00cd21b74093ba0001b9be04cd21c3b4 }


condition:
	$a0
}