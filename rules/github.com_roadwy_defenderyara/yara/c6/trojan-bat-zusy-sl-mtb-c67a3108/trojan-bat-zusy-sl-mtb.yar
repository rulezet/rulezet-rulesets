rule Trojan_BAT_Zusy_SL_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 07 06 11 04 11 06 11 07 6f b4 00 00 0a 00 11 06 17 d6 13 06 11 06 11 05 31 bf } 		$a_81_1 = {46 61 6b 69 6c 61 68 61 72 69 6f 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}