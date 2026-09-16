rule FakeNinjav28Spirit
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BA [4] FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 }

condition:
		$a0
}