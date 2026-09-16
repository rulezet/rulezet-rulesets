rule Trojan_BAT_Injuke_SG_MTB_2{
	meta:
		description = "Trojan:BAT/Injuke.SG!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 44 6f 6d 61 69 6e } 		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 		$a_01_2 = {73 69 6d 70 6c 65 43 41 6c 63 75 6c 61 74 6f 72 45 78 63 65 70 74 69 6f 6e 5f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}