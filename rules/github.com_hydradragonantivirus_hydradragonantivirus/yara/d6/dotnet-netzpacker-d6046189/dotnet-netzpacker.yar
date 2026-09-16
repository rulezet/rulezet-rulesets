import "pe"
rule DotNET_NetzPacker : MadeBits
{
	meta:
		author="_pusher_"
		date="2016-07"
	strings:		
		$a0 = "NetzStarter" wide ascii nocase
		$a1 = "netz\x00mscorlib" wide ascii nocase
		$a2 = "NetzSuffix" wide ascii nocase
		$a3 = "NetzResolveEventHandler" wide ascii nocase
	condition:
		(pe.imports ("mscoree.dll","_CorExeMain") or pe.imports ("mscoree.dll","_CorDllMain")) and 4 of ($a*)		
}