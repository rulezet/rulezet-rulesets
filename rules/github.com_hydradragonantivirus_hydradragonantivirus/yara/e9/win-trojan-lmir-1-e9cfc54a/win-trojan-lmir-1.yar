rule Win_Trojan_Lmir_1
{
strings:
	$a0 = { b34f53542e455845730b1e8da8d070e7430587c5fec9134d41494c4d4f4e283b4b5bfd3ff94156504657bdadc3f1c9b1b6bec8ed6a208d77ffff4b5632303034a3bacab5cab1bce0cad32b5261764da8f11d0f }


condition:
	$a0
}