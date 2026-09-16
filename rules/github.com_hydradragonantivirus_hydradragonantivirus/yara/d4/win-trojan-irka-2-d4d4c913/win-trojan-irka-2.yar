rule Win_Trojan_Irka_2
{
strings:
	$a0 = { d32bd03ac9bafd2d44b1b44045e9a3bab8d40711afed7db1abb8b0d7fc88f0c8abf5ff8d45 }


condition:
	$a0
}