rule OPCLEAVER_wndTest
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "f8daa0a8-f0f0-5bf7-b9ab-eaf5335ff2b9"
	strings:
		$s1 = "[Alt]" wide
		$s2 = "<< %s >>:" wide
		$s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"
	condition:
		all of them
}