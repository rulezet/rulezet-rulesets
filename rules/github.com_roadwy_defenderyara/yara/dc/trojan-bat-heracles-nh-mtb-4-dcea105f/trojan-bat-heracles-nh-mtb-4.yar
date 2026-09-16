rule Trojan_BAT_Heracles_NH_MTB_4{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 43 6b 72 4a 72 75 59 57 47 73 49 45 4a 4d 46 57 78 52 63 6d } 		$a_01_1 = {46 4e 44 4f 4a 62 74 73 58 71 65 54 58 6e 78 74 } 		$a_01_2 = {54 65 73 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 31 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}