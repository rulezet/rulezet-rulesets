rule EQGRP_installdate {
	meta:
		description = "Detects tool from EQGRP toolset - file installdate.pl"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "029b1213-1206-5b7c-bd72-93239a23fe8a"
	strings:
		$x1 = "#Provide hex or EP log as command-line argument or as input" fullword ascii
		$x2 = "print \"Gimme hex: \";" fullword ascii
		$x3 = "if ($line =~ /Reg_Dword:  (\\d\\d:\\d\\d:\\d\\d.\\d+ \\d+ - )?(\\S*)/) {" fullword ascii

		$s1 = "if ($_ =~ /InstallDate/) {" fullword ascii
		$s2 = "if (not($cmdInput)) {" fullword ascii
		$s3 = "print \"$hex in decimal=$dec\\n\\n\";" fullword ascii
	condition:
		filesize < 2KB and ( 1 of ($x*) or 3 of them )
}