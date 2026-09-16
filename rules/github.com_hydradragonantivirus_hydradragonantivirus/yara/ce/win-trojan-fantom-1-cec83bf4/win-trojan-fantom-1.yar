rule Win_Trojan_Fantom_1
{
strings:
	$a0 = { bc007cb8809f8ec0506a4dba8000b90200b80402cd13cb }


condition:
	$a0
}