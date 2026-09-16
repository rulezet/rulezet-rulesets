rule RAT_SmallNet
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects SmallNet RAT"
		reference = "http://malwareconfig.com/stats/SmallNet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "aec1f8fd-2806-527e-9d50-422f212864de"
	strings:
		$split1 = "!!<3SAFIA<3!!"
		$split2 = "!!ElMattadorDz!!"
		$a1 = "stub_2.Properties"
		$a2 = "stub.exe" wide
		$a3 = "get_CurrentDomain"

	condition:
		($split1 or $split2) and (all of ($a*))
}