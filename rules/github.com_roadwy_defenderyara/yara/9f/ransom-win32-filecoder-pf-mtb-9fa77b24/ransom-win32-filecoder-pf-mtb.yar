rule Ransom_Win32_Filecoder_PF_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 55 fc c6 04 02 00 c6 00 00 8a 14 06 2a d1 fe ca 88 14 07 41 40 3b 4d f8 76 } 		$a_02_1 = {8b 08 8b f1 c1 ee ?? 33 f1 69 f6 ?? ?? ?? ?? 03 f2 89 70 04 83 c0 04 42 3d ?? ?? ?? ?? 7c } 	condition:
		((#a_00_0  & 1)*4+(#a_02_1  & 1)*1) >=5
 
}