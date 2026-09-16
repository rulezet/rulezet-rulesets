rule PEProtect09byCristophGabler1998
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 }

condition:
		$a0
}