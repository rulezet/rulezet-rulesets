rule CN_Honker_Webshell_mycode12 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mycode12.cfm"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "64be8760be5ab5c2dcf829e3f87d3e50b1922f17"
		id = "2ce7368c-7565-5b32-94d1-c87023404c5b"
	strings:
		$s1 = "<cfexecute name=\"cmd.exe\"" fullword ascii 
		$s2 = "<cfoutput>#cmd#</cfoutput>" fullword ascii
	condition:
		filesize < 4KB and all of them
}