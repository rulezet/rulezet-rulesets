rule Trojan_BAT_Rozena_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Rozena.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 49 06 07 06 8e 69 5d 93 61 d1 53 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d dd } 		$a_80_1 = {3a 2f 2f 6a 63 78 6a 67 2e 66 75 6e 2f 74 65 73 74 2f 64 65 5f 73 68 65 6c 6c 63 6f 64 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}