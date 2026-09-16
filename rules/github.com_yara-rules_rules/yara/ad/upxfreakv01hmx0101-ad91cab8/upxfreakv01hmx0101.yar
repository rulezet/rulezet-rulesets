import "pe"
rule UPXFreakV01HMX0101
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BE [4] 83 C6 01 FF E6 00 00 }

condition:
		$a0 at pe.entry_point
}