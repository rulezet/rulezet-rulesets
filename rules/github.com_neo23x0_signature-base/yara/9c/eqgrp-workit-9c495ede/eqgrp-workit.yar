rule EQGRP_workit {
	meta:
		description = "EQGRP Toolset Firewall - file workit.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		modified = "2023-01-27"
		hash1 = "fb533b4d255b4e6072a4fa2e1794e38a165f9aa66033340c2f4f8fd1da155fac"
		id = "b582f990-5bd5-592d-a7c0-475fdfffc38c"
	strings:
		$s1 = "macdef init > /tmp/.netrc;" fullword ascii
		$s2 = "/usr/bin/wget http://" ascii
		$s3 = "HOME=/tmp ftp" fullword ascii
		$s4 = " >> /tmp/.netrc;" fullword ascii
		$s5 = "/usr/rapidstream/bin/tftp" fullword ascii
		$s6 = "created shell_command:" fullword ascii
		$s7 = "rm -f /tmp/.netrc;" fullword ascii
		$s8 = "echo quit >> /tmp/.netrc;" fullword ascii
		$s9 = "echo binary >> /tmp/.netrc;" fullword ascii
		$s10 = "chmod 600 /tmp/.netrc;" fullword ascii
		$s11 = "created cli_command:" fullword ascii
	condition:
		6 of them
}