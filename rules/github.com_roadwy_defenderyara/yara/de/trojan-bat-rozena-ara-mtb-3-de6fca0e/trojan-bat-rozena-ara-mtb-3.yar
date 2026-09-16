rule Trojan_BAT_Rozena_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/Rozena.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 0d 09 2d e1 } 		$a_80_1 = {49 6e 76 6f 6b 65 53 68 65 6c 6c 63 6f 64 65 63 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*1) >=3
 
}