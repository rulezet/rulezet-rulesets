rule OPCLEAVER_zhLookUp
{
	meta:
		description = "Hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "45ef9a90-db4c-59c3-b694-da3f539b118b"
	strings:
		$s1 = "zhLookUp.Properties"
	condition:
		all of them
}