import "pe"
rule VcasmProtector10evcasm
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D }

condition:
		$a0 at pe.entry_point
}