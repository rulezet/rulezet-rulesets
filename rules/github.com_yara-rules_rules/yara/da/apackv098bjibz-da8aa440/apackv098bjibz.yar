rule aPackv098bJibz
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 93 07 1F 05 [2] 8E D0 BC [2] EA }

condition:
		$a0
}