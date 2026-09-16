rule fmlibraryv3 {
	meta:
		description = "Webshells Auto-generated - file fmlibraryv3.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "c34c248fed6d5a20d8203924a2088acc"
	strings:
		$s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER"
	condition:
		all of them
}