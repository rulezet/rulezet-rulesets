rule webshell_asp_cmd : webshell {
	meta:
		description = "Web Shell - file cmd.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "895ca846858c315a3ff8daa7c55b3119"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
		$s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
		$s3 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
	condition:
		1 of them
}