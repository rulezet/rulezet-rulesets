rule Win_Trojan_Burma_4
{
strings:
	$a0 = { b90200b44ebad101cd21b43c33c9ba9e00cd21b74093ba0001b9ba01cd21c3 }


condition:
	$a0
}