import "pe"
rule _W32Jeefo_PE_File_Infector_
{
	meta:
		description = "W32.Jeefo (PE File Infector)"
	strings:
		$0 = {55 89 E5 83 EC 08 83 C4 F4 6A 02 A1 C8 ?? ?? ?? FF D0 E8 ?? ?? ?? ?? C9 C3}
	condition:
		$0 at pe.entry_point
}