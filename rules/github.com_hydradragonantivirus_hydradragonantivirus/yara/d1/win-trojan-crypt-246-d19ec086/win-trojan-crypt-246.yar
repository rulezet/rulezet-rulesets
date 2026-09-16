rule Win_Trojan_Crypt_246
{
strings:
	$a0 = { 558bec83c4f0b87c694700e804f4f8ffa1a88a47008b00e8 }

	$a1 = { 69645f73697465 }

	$a2 = { 5450463005547a69636104 }

	$a3 = { 6275736361 }


condition:
	$a0 and $a1 and $a2 and $a3
}