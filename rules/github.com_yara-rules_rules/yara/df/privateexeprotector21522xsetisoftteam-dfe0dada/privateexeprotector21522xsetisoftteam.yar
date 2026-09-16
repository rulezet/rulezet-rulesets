rule PrivateexeProtector21522XSetiSoftTeam
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 }

condition:
		$a0
}