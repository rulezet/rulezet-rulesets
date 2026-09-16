rule Win_Spyware_Banker_3320
{
strings:
	$a0 = { 37334ddc4cc7b3dd896d1913eb4078103b1bf2f77fee3bab5f8e302358c29d0d64f3928876d907d270347de5a548d40ddc54a2eca0ef5d5b62e09f118ada8409f4cbf9093c5e }


condition:
	$a0
}