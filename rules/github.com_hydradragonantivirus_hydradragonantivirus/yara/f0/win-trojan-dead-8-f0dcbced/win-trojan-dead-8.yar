rule Win_Trojan_Dead_8
{
strings:
	$a0 = { 7200b440b99a028d961b05cd21b80242e864002d04003e8986c104b440b932018d96bf03cd21b8 }


condition:
	$a0
}