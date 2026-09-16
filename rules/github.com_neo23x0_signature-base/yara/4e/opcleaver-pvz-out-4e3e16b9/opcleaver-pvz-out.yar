rule OPCLEAVER_pvz_out
{
	meta:
		description = "Parviz tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "46b51bff-dfd9-5f56-897c-422112bc837b"
	strings:
		$s1 = "Network Connectivity Module" wide
		$s2 = "OSPPSVC" wide
	condition:
		all of them
}