rule UPXHiTv001DJSiba
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 94 BC [3] 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }

condition:
		$a0
}