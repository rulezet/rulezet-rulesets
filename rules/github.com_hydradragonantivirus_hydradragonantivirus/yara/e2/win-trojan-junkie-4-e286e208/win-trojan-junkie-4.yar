rule Win_Trojan_Junkie_4
{
strings:
	$a0 = { af21b9f4012681342bb04646e2f7 }


condition:
	$a0
}