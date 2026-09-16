rule OPCLEAVER_BackDoorLogger
{
	meta:
		description = "Keylogger used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "e9149baa-83c0-597f-833c-ea0241bb60e6"
	strings:
		$s1 = "BackDoorLogger"
		$s2 = "zhuAddress"
	condition:
		all of them
}