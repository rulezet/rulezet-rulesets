rule asp_dns {
	meta:
		description = "Laudanum Injector Tools - file dns.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "5532154dd67800d33dace01103e9b2c4f3d01d51"
		id = "b0e30ca0-7163-5731-98c5-5a1893b8ea80"
	strings:
		$s1 = "command = \"nslookup -type=\" & qtype & \" \" & query " fullword ascii 
		$s2 = "Set objCmd = objWShell.Exec(command)" fullword ascii 
		$s3 = "Response.Write command & \"<br>\"" fullword ascii 
		$s4 = "<form name=\"dns\" method=\"POST\">" fullword ascii 
	condition:
		filesize < 21KB and all of them
}