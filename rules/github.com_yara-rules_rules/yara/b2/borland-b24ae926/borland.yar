rule Borland
{
      meta:
		author="malware-lu"
	strings:
		$patternBorland = "Borland" wide ascii
	condition:
		$patternBorland
}