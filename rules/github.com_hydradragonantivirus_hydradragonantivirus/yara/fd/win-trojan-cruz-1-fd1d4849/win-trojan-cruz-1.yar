rule Win_Trojan_Cruz_1
{
strings:
	$a0 = { d6005589e531c09a3005d600e841f7e809fd803e5400007503e837fec931c09a1601d6000000558becb42acd21 }


condition:
	$a0
}