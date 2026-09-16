rule OPCLEAVER_SmartCopy2
{
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "898d9060-208a-5dfb-a452-50ab49b80a9d"
	strings:
		$s1 = "SmartCopy2.Properties"
		$s2 = "ZhuFrameWork"
	condition:
		all of them
}