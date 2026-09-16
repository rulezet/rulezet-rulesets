rule Win_Trojan_Murcia_1
{
strings:
	$a0 = { 01b943112bcf2ea0ff122805fec047e2f9c3b42ccd212e8816ff128b0ea601890efd12c60600130190e8beff2ec6 }


condition:
	$a0
}