import "pe"
rule _Packman_Executable_Image_Packer_0001__bubba_
{
	meta:
		description = "Packman Executable Image Packer 0.0.0.1 -> bubba"
	strings:
		$0 = {60 E8 00 00 00 00 58 8D A8 ?? ?? FF FF 8D 98 ?? ?? ?? FF}
	condition:
		$0 at pe.entry_point
}