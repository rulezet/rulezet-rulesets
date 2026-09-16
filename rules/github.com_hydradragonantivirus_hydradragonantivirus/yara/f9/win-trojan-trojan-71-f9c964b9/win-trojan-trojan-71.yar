rule Win_Trojan_Trojan_71
{
strings:
	$a0 = { 0200b44ebaa80190cd21b8023c33c9ba9e00cd21b74093 }


condition:
	$a0
}