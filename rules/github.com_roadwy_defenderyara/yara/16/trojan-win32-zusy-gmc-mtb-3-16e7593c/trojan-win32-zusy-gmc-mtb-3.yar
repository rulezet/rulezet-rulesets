rule Trojan_Win32_Zusy_GMC_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 8b 45 fc 8d 04 86 50 56 57 e8 ?? ?? ?? ?? 8b 45 fc 83 c4 14 48 89 35 a8 bc 45 01 5f 5e a3 a4 bc 45 01 5b c9 c3 } 		$a_80_1 = {53 74 65 61 6d 53 65 72 76 69 63 65 2e 65 78 65 } 		$a_01_2 = {40 2e 69 38 31 35 } 	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}