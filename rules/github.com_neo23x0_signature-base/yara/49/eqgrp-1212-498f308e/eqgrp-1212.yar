rule EQGRP_1212 {
	meta:
		description = "Detects tool from EQGRP toolset - file 1212.pl"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "428fed4f-df5c-5fc2-ac4b-4dea69ea4f2d"
	strings:
		$s1 = "if (!(($srcip,$dstip,$srcport,$dstport) = ($line=~/^([a-f0-9]{8})([a-f0-9]{8})([a-f0-9]{4})([a-f0-9]{4})$/)))" fullword ascii
		$s2 = "$ans=\"$srcip:$srcport -> $dstip:$dstport\";" fullword ascii
		$s3 = "return \"ERROR:$line is not a valid port\";" fullword ascii
		$s4 = "$dstport=hextoPort($dstport);" fullword ascii
		$s5 = "sub hextoPort" fullword ascii
		$s6 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
	condition:
		filesize < 6KB and 4 of them
}