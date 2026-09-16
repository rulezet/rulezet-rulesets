rule EQGRP_1212_dehex {
	meta:
		description = "Detects tool from EQGRP toolset - from files 1212.pl, dehex.pl"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "2cc375e6-2bff-5623-b86c-a6413f736c42"
	strings:
		$s1 = "return \"ERROR:$line is not a valid address\";" fullword ascii
		$s2 = "print \"ERROR: the filename or hex representation needs to be one argument try using \\\"'s\\n\";" fullword ascii
		$s3 = "push(@octets,$byte_table{$tempi});" fullword ascii
		$s4 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
		$s5 = "print hextoIP($ARGV[0]);" fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 6KB and ( 5 of ($s*) ) ) or ( all of them )
}