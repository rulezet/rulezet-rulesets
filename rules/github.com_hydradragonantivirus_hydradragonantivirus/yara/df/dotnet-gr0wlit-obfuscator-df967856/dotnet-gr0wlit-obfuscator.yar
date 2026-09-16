import "pe"
rule DotNET_Gr0wlit_Obfuscator : Gr0wlit
{
	meta:
		author="_pusher_"
		date="2016-07"
	strings:		
		$a0 = "Gr0wlit_" wide ascii nocase
	condition:
		(pe.imports ("mscoree.dll","_CorExeMain") or pe.imports ("mscoree.dll","_CorDllMain")) and 1 of ($a*)		
}