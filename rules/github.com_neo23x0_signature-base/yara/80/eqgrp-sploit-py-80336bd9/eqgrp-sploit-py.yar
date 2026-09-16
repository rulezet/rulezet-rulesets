rule EQGRP_sploit_py {
	meta:
		description = "EQGRP Toolset Firewall - file sploit.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
		id = "9f403965-5fb1-55b2-bef6-65c18e08e58f"
	strings:
		$x1 = "the --spoof option requires 3 or 4 fields as follows redir_ip" ascii
		$x2 = "[-] timeout waiting for response - target may have crashed" fullword ascii
		$x3 = "[-] no response from health check - target may have crashed" fullword ascii
	condition:
		1 of them
}