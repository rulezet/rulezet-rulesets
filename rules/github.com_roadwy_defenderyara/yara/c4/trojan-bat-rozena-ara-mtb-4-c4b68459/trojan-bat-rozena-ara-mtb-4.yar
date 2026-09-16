rule Trojan_BAT_Rozena_ARA_MTB_4{
	meta:
		description = "Trojan:BAT/Rozena.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 09 06 09 91 1f 22 59 1f 4a 61 20 ff 00 00 00 5f d2 9c 09 17 58 0d 09 06 8e 69 32 e3 } 		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } 		$a_01_2 = {43 72 65 61 74 65 54 68 72 65 61 64 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}