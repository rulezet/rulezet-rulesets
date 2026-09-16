rule Trojan_BAT_Tedy_ARA_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 91 0d 06 07 06 08 91 9c 06 08 09 d2 9c 07 17 58 0b 08 17 59 0c 07 08 32 e5 } 		$a_01_1 = {45 68 6a 69 6f 67 65 72 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}