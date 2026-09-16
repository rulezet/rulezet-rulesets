import "pe"
rule Mystic_Compressor120203
{
		meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { 46 6C 73 41 6C 6C 6F 63 }
		$a1 = { 44 65 6C 70 68 69 41 70 70 6C 69 63 61 74 69 6F 6E }
	condition:
		pe.imports ("kernel32.dll","GetProcAddress") and
		pe.imports ("kernel32.dll","GetStartupInfoW") and
		pe.imports ("kernel32.dll","GetOEMCP") and
		pe.imports ("kernel32.dll","IsDebuggerPresent") and
		$a0 and $a1
}