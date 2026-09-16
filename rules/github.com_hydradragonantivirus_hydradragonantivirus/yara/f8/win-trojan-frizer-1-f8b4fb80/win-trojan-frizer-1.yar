rule Win_Trojan_Frizer_1
{
strings:
	$a0 = { 4059ba0001fecdcd211fff064e04b43ecd21833e4e040a7503bd2804b44fcd21bd38037303bdf6 }


condition:
	$a0
}