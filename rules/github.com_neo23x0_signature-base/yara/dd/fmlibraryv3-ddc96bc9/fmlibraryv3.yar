rule fmlibraryv3 {
	meta:
		description = "Webshells Auto-generated - file fmlibraryv3.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "c34c248fed6d5a20d8203924a2088acc"
		id = "9b8ef79d-80bb-5a05-91e6-0f2bc3fd3068"
	strings:
		$s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER"
	condition:
		all of them
}