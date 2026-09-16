rule Win_Trojan_Trivial_417
{
strings:
	$a0 = { b4403e3e3e3e3e3e3e3e3e3e3e3eb9d6003e3e3e3e3e3e3e3e3e3e3e3eba0001cd213e3e3e3e3e3e3e3e3e3e3e3e3eb43ecd21 }


condition:
	$a0
}