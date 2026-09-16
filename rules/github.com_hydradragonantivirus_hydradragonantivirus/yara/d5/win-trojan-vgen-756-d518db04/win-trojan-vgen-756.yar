rule Win_Trojan_VGEN_756
{
strings:
	$a0 = { b9c103bd0000bed403cd012e813400004ee2f89ccd019c585b3bc37402cd200e171e06fc0e1fb42acd2180fe0c752b }


condition:
	$a0
}