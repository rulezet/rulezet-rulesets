rule Trojan_Win64_DonutLoader_TL_MTB_2{
	meta:
		description = "Trojan:Win64/DonutLoader.TL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 98 0f b6 4c 05 80 8b 85 84 00 00 00 48 63 d0 48 8b 85 a0 00 00 00 48 01 d0 44 89 c2 31 ca 88 10 83 85 84 00 00 00 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}