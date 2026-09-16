rule Trojan_Win32_Emotet_DEM_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d3 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 1c 8b 44 24 24 41 89 4c 24 1c 8a 54 14 28 30 54 01 ff } 		$a_81_1 = {75 6a 74 6a 4b 44 4f 64 37 42 41 77 42 66 4d 62 33 31 31 63 56 71 43 77 63 49 36 65 4a 76 6e 6a 61 41 } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}