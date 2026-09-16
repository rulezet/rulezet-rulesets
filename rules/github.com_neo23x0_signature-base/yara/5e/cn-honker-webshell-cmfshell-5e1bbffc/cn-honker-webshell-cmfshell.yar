rule CN_Honker_Webshell_cmfshell {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file cmfshell.cmf"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b9b2107c946431e4ad1a8f5e53ac05e132935c0e"
		id = "c5670deb-952c-5ba4-949a-097cc09bb108"
	strings:
		$s1 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii 
		$s2 = "<form action=\"<cfoutput>#CGI.SCRIPT_NAME#</cfoutput>\" method=\"post\">" fullword ascii 
	condition:
		filesize < 4KB and all of them
}