rule Trojan_BAT_Zusy_NK_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 00 17 64 13 00 ?? ?? 00 00 00 11 01 11 00 11 04 17 59 5f 59 13 01 } 		$a_01_1 = {11 03 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60 13 03 } 		$a_81_2 = {54 79 72 6f 6e 65 2e 64 6c 6c } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}