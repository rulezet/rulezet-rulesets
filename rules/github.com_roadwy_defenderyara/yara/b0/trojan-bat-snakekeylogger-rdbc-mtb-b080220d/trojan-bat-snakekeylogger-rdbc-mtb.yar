rule Trojan_BAT_SnakeKeyLogger_RDBC_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 61 70 74 75 72 65 20 52 65 63 6f 76 65 72 79 20 54 6f 6f 6c } 		$a_01_1 = {54 65 63 68 53 6d 69 74 68 20 43 6f 72 70 6f 72 61 74 69 6f 6e } 		$a_01_2 = {43 61 6d 74 61 73 69 61 20 53 74 75 64 69 6f } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}