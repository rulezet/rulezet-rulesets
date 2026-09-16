rule Win_Trojan_BOO_10
{
strings:
	$a0 = { 4c008f064e00c70660001b018c0662000e07bb0002b9080032f6e85f00b404cd1a81fa1009 }


condition:
	$a0
}