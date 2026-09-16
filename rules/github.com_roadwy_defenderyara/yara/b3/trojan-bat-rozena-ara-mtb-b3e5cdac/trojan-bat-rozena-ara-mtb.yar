rule Trojan_BAT_Rozena_ARA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 61 d2 9c 07 17 58 0b 07 02 8e 69 32 ed } 		$a_01_1 = {53 68 65 6c 6c 63 6f 64 65 52 75 6e 6e 65 72 5f 65 76 61 73 69 6f 6e 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}