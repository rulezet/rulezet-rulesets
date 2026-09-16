rule Trojan_BAT_Heracles_MBX_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 		$a_01_1 = {53 00 65 00 6e 00 69 00 6f 00 72 00 00 11 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 00 0f 4c 00 20 00 6f 00 20 00 61 00 20 00 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}