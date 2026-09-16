rule Ajan_asp {
	meta:
		description = "Semi-Auto-generated  - file Ajan.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b6f468252407efc2318639da22b08af0"
		id = "6040fd88-b992-5110-8b37-7711ace30b1a"
	strings:
		$s1 = "c:\\downloaded.zip"
		$s2 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)" fullword
		$s3 = "http://www35.websamba.com/cybervurgun/"
	condition:
		1 of them
}