rule FSO_s_tool {
	meta:
		description = "Webshells Auto-generated - file tool.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3a1e1e889fdd974a130a6a767b42655b"
	strings:
		$s7 = "\"\"%windir%\\\\calc.exe\"\")"
	condition:
		all of them
}