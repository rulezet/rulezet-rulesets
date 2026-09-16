rule BIN_Server {
	meta:
		description = "Webshells Auto-generated - file Server.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1d5aa9cbf1429bb5b8bf600335916dcd"
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