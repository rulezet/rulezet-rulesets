rule OPCLEAVER_Parviz_Developer
{
	meta:
		description = "Parviz developer known from Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		id = "2bfa90a0-0495-5b21-98f7-5ed7ebc74b2d"
	strings:
		$s1 = "Users\\parviz\\documents\\" nocase
	condition:
		$s1
}