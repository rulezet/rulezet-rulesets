rule FSO_s_ajan_2 {
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "22194f8c44524f80254e1b5aec67b03e"
	strings:
		$s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")"
		$s3 = "/file.zip"
	condition:
		all of them
}