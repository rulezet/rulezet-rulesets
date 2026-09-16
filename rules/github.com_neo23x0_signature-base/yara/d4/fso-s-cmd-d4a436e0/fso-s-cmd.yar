rule FSO_s_cmd {
	meta:
		description = "Webshells Auto-generated - file cmd.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cbe8e365d41dd3cd8e462ca434cf385f"
		id = "f7a74f21-aec9-5ee7-a80e-0fe34b977a71"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
		$s1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
	condition:
		all of them
}