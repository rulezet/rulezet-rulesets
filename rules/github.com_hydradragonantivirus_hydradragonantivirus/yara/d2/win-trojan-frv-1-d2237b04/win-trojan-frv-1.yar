rule Win_Trojan_FRV_1
{
strings:
	$a0 = { 434f4d142f4320434f5059202f426672765f312e746d702b05203e4e554c5589e5b886329acd02 }


condition:
	$a0
}