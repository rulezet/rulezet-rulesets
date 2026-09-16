rule FSO_s_tool {
	meta:
		description = "Webshells Auto-generated - file tool.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3a1e1e889fdd974a130a6a767b42655b"
		id = "ed744aa4-7a35-57d6-89bd-3286a21b50a0"
	strings:
		$s7 = "\"\"%windir%\\\\calc.exe\"\")"
	condition:
		all of them
}