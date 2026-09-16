rule AsCryptv01SToRM4
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 80 [3] 83 [4] 90 90 90 E2 }

condition:
		$a0
}