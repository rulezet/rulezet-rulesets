rule Reader_asp {
	meta:
		description = "Semi-Auto-generated  - file Reader.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ad1a362e0a24c4475335e3e891a01731"
		id = "70094d24-fa3a-503c-b9b6-294a883fc52c"
	strings:
		$s1 = "Mehdi & HolyDemon"
		$s2 = "www.infilak."
		$s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%"
	condition:
		2 of them
}