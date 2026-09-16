rule Win_Trojan_Virut_387
{
strings:
	$a0 = { 33c9b104014c24??e9??????00 }


condition:
	$a0
}