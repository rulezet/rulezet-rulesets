rule Win_Trojan_Attack_1
{
strings:
	$a0 = { b903005e5f5756ba200d03d61e8edfcd211fb442b002b90000ba0000cd21061fb440b9000e }


condition:
	$a0
}