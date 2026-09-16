rule Win_Trojan_DosProb_1
{
strings:
	$a0 = { ee0400bbfefff616f204eb14803eef0401750ac606ef0400bbffffeb0333dbc3c606f00401f8 }


condition:
	$a0
}