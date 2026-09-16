rule Win_Trojan_Leonard_1
{
strings:
	$a0 = { d95683c672908bfe4eb93704d9d0fcac32042ac2aae2f8 }


condition:
	$a0
}