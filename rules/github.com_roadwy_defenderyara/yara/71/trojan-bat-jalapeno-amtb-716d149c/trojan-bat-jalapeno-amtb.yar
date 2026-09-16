rule Trojan_BAT_Jalapeno_AMTB{
	meta:
		description = "Trojan:BAT/Jalapeno!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 31 35 35 2e 31 31 37 2e 34 30 2e 32 32 31 2f } 		$a_80_1 = {78 68 73 71 69 67 62 34 2e 69 6f 70 2e 65 78 65 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}