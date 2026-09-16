rule PrivateEXEProtector18
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BB DC EE 0D 76 D9 D0 8D 16 85 D8 90 D9 D0 }

condition:
		$a0
}