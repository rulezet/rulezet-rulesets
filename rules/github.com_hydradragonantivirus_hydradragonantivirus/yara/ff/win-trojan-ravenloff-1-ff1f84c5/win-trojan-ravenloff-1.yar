rule Win_Trojan_Ravenloff_1
{
strings:
	$a0 = { 71723dbe5b00ad3b475b7434b80103b601b10e807f15f97402b110890e4b00cd71721dbe0202bf }


condition:
	$a0
}