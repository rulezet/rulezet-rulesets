rule EQGRP_durablenapkin_solaris_2_0_1 {
	meta:
		description = "Detects tool from EQGRP toolset - file durablenapkin.solaris.2.0.1.1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "7b49a26d-9ee3-5aff-93fc-509239daef28"
	strings:
		$s1 = "recv_ack: %s: Service not supplied by provider" fullword ascii
		$s2 = "send_request: putmsg \"%s\": %s" fullword ascii
		$s3 = "port undefined" fullword ascii
		$s4 = "recv_ack: %s getmsg: %s" fullword ascii
		$s5 = ">> %d -- %d" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and 2 of them )
}