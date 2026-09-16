rule Win_Trojan_Three6_1
{
strings:
	$a0 = { ba0000b000cd215ab440b90300cd2153b442b90000ba0000b002cd21bb01018b070503018bd0bb01 }


condition:
	$a0
}