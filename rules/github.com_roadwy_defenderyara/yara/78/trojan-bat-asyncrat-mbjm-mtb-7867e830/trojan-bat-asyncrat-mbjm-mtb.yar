rule Trojan_BAT_AsyncRAT_MBJM_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 0f 02 11 0f 91 11 0d 61 11 09 11 07 91 61 b4 9c 11 07 03 6f ?? 00 00 0a 17 da 33 05 } 		$a_01_1 = {76 00 69 00 56 00 76 00 53 00 66 00 74 00 62 00 73 00 65 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}