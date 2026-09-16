rule Win_Trojan_Lovechild_1
{
strings:
	$a0 = { 03cd13fece79f7b603fec5ebf14c6f76 }


condition:
	$a0
}