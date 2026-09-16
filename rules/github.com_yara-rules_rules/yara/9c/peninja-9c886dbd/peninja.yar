import "pe"
rule PENinja: Packer PEiD
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at pe.entry_point
}