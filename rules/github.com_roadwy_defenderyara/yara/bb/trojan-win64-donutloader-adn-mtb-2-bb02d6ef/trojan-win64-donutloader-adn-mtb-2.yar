rule Trojan_Win64_DonutLoader_ADN_MTB_2{
	meta:
		description = "Trojan:Win64/DonutLoader.ADN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 89 f0 48 f7 d8 0f 80 ?? 09 00 00 4c 8b ?? ?? 04 00 00 48 8d 0d ?? ?? 01 00 e8 ?? ?? 01 00 48 85 c0 0f 84 ?? 09 00 00 49 89 ?? 48 8d 15 ?? ?? 01 00 48 89 c1 } 		$a_01_1 = {73 69 6c 65 6e 74 72 69 66 74 5f 6c 6f 61 64 65 72 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}