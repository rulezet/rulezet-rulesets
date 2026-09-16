rule Trojan_Win32_LummaC_GTZ_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {40 00 00 e0 2e 74 ?? 67 67 61 6e 74 00 40 00 00 00 20 44 00 00 22 00 } 		$a_80_1 = {64 65 66 4f 66 66 2e 65 78 65 } 		$a_80_2 = {6f 66 66 44 65 66 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}