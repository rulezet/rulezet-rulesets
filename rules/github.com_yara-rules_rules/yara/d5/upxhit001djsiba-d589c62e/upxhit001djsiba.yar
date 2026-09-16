rule UPXHiT001DJSiba
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E2 FA 94 FF E0 61 00 00 00 00 00 00 00 }

condition:
		$a0
}