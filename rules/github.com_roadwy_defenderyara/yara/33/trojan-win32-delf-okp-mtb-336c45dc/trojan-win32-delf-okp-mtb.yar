rule Trojan_Win32_Delf_OKP_MTB{
	meta:
		description = "Trojan:Win32/Delf.OKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b f0 89 77 14 89 7e 0c c7 46 ?? ?? ?? ?? ?? 8d 47 38 89 46 14 c7 47 ?? ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 88 47 08 8b d7 a1 } 		$a_00_1 = {64 52 41 4e 47 45 52 4f } 		$a_00_2 = {4f 4d 4e 54 41 41 41 41 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}