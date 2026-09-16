rule EQGRP_eligiblecandidate {
	meta:
		description = "EQGRP Toolset Firewall - file eligiblecandidate.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "c4567c00734dedf1c875ecbbd56c1561a1610bedb4621d9c8899acec57353d86"
		id = "e084b051-4aa1-54b2-9f56-69db386b46d6"
	strings:
		$o1 = "Connection timed out. Only a problem if the callback was not received." fullword ascii
		$o2 = "Could not reliably detect cookie. Using 'session_id'..." fullword ascii

		$c1 = "def build_exploit_payload(self,cmd=\"/tmp/httpd\"):" fullword ascii
		$c2 = "self.build_exploit_payload(cmd)" fullword ascii
	condition:
		1 of them
}