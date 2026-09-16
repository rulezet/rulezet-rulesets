rule Trojan_BAT_Rozena_ARA_MTB_5{
	meta:
		description = "Trojan:BAT/Rozena.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 21 00 02 06 8f ?? ?? ?? 01 25 71 ?? ?? ?? 01 03 06 03 8e 69 5d 91 61 d2 81 ?? ?? ?? 01 00 06 17 58 0a 06 02 8e 69 fe 04 0c 08 2d d5 02 0b 2b 00 07 2a } 		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_01_2 = {43 72 65 61 74 65 54 68 72 65 61 64 } 		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}