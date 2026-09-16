rule OPCLEAVER_NetC
{
	meta:
		description = "Net Crawler used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "68f32662-0d7d-5dfa-8bfd-ca41d383e19c"
	strings:
		$s1 = "NetC.exe" wide
		$s2 = "Net Service"
	condition:
		all of them
}