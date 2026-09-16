rule IronTiger_Gh0stRAT_variant
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "This is a detection for a s.exe variant seen in Op. Iron Tiger"
		reference = "http://goo.gl/T5fSJC"
		id = "e7eeee0f-d7a1-5359-bc1f-5a2a883c7227"
	strings:
		$str1 = "Game Over Good Luck By Wind" nocase wide ascii
		$str2 = "ReleiceName" nocase wide ascii
		$str3 = "jingtisanmenxiachuanxiao.vbs" nocase wide ascii
		$str4 = "Winds Update" nocase wide ascii fullword
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
		and not filename == "UpdateSystemMib.exe"
}