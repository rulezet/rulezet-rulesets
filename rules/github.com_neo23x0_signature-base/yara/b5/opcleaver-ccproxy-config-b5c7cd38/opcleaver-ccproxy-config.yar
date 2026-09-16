rule OPCLEAVER_CCProxy_Config
{
	meta:
		description = "CCProxy config known from Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		id = "c4d80a2a-2a32-585e-bc20-1c5118e4ee48"
	strings:
		$s1 = "UserName=User-001" fullword ascii
		$s2 = "Web=1" fullword ascii
		$s3 = "Mail=1" fullword ascii
		$s4 = "FTP=0" fullword ascii
		$x1 = "IPAddressLow=78.109.194.114" fullword ascii
	condition:
		all of ($s*) or $x1
}