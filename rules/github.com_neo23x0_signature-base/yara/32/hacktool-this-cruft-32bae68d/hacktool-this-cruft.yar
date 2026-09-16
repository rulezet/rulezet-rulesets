rule Hacktool_This_Cruft {
	meta:
		description = "Detects string 'This cruft' often used in hack tools like netcat or cryptcat and also mentioned in Project Sauron report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"
		score = 60
		id = "a39de541-19b5-5b7e-a3dc-51a5309181e5"
	strings:
		$x1 = "This cruft" fullword
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and $x1 )
}