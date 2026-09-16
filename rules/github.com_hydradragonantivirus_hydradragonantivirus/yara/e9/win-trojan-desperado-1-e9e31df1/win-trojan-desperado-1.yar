rule Win_Trojan_Desperado_1
{
strings:
	$a0 = { f583fa0075de37b003585dd9ed1202a41d5e05e0226dce7904d9f8e4022c55ec33952264002a4d465b108d80836603 }


condition:
	$a0
}