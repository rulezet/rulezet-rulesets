rule Win_Trojan_WickedRage_1
{
strings:
	$a0 = { b90100ba80008d9e0201cd13b002b901008d9e020133d2cd264273fbb4098d969403cd21eb }


condition:
	$a0
}