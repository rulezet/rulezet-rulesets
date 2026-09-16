rule Win_Virus_Floxif_2
{
strings:
	$a0 = { 894424f8e8[4]c3ff608bec83c5245464a1300000008b400c8b701cad }


condition:
	$a0
}