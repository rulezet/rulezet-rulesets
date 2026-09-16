rule BIN_Server {
	meta:
		description = "Webshells Auto-generated - file Server.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1d5aa9cbf1429bb5b8bf600335916dcd"
		id = "1625b0ee-5f9f-57d8-8333-f175f46d6c59"
	strings:
		$s0 = "configserver"
		$s1 = "GetLogicalDrives"
		$s2 = "WinExec"
		$s4 = "fxftest"
		$s5 = "upfileok"
		$s7 = "upfileer"
	condition:
		all of them
}