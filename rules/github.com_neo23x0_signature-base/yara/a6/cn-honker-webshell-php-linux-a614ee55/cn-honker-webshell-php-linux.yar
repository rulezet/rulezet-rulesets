rule CN_Honker_Webshell_PHP_linux {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file linux.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "78339abb4e2bb00fe8a012a0a5b7ffce305f4e06"
		id = "8d94f1c5-2139-5d0d-8af9-9c30a0359910"
	strings:
		$s0 = "<form name=form1 action=exploit.php method=post>" fullword ascii 
		$s1 = "<title>Changing CHMOD Permissions Exploit " fullword ascii
	condition:
		uint16(0) == 0x696c and filesize < 6KB and all of them
}