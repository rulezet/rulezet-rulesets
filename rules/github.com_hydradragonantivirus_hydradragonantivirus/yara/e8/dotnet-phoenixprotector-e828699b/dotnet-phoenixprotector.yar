import "pe"
rule DotNET_PhoenixProtector : NTCore
{
	meta:
		author="_pusher_"
		date="2016-07"
	strings:	
		$a0 = { 02 ?? ?? 00 00 ?? 0A 06 ?? ?? 00 00 01 0B 16 0C ?? ?? ?? ?? ?? 02 08 ?? ?? ?? ?? ?? 0D 09 06 08 59 61 D2 13 04 09 1E 63 08 61 D2 13 05 07 08 11 05 1E 62 11 04 60 D1 9D 08 17 58 }
	condition:
		(pe.imports ("mscoree.dll","_CorExeMain") or pe.imports ("mscoree.dll","_CorDllMain")) and 1 of ($a*)
}