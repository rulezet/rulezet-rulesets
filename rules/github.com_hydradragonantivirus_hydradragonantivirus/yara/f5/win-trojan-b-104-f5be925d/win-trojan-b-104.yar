rule Win_Trojan_B_104
{
strings:
	$a0 = { 33dbb90100e8120007c30e1fb92400be05008bfb03fefcf3a6c3 }


condition:
	$a0
}