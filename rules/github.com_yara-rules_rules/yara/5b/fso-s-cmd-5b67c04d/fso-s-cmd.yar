rule FSO_s_cmd {
	meta:
		description = "Webshells Auto-generated - file cmd.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cbe8e365d41dd3cd8e462ca434cf385f"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
		$s1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
	condition:
		all of them
}