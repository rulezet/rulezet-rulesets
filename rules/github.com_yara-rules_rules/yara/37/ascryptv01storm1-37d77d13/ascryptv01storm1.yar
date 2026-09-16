rule AsCryptv01SToRM1
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 81 [6] 83 [7] 83 [2] E2 ?? EB }

condition:
		$a0
}