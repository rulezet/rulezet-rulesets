rule Win_Trojan_Eek_1
{
strings:
	$a0 = { 03e8b40683c408eb218bc603c73b06ae007e068b3eae002bfe578d86f8fd50ff76fce8181d }


condition:
	$a0
}