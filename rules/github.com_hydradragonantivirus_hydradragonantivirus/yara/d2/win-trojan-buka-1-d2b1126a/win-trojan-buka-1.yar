rule Win_Trojan_Buka_1
{
strings:
	$a0 = { 1050100e10d174af5f10e91056a3e1109d104c47c3108d10448e8610a11041c98010c465596b }


condition:
	$a0
}