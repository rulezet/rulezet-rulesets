rule SCT_Scriptlet_in_Temp_Inet_Files {
	meta:
		description = "Detects a scriptlet file in the temporary Internet files (see regsvr32 AppLocker bypass)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/KAB8Jw"
		date = "2016-04-26"
		id = "8b729257-3676-59b2-961c-dae1085cbbf6"
	strings:
		$s1 = "<scriptlet>" fullword ascii nocase
		$s2 = "ActiveXObject(\"WScript.Shell\")" ascii
	condition:
		( uint32(0) == 0x4D583F3C or uint32(0) == 0x6D78F3C ) 
		and $s1 and $s2
		and filepath contains "Temporary Internet Files"
}