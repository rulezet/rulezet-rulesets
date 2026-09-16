rule Trojan_BAT_Seraph_AMBA_MTB_3{
	meta:
		description = "Trojan:BAT/Seraph.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 16 d2 13 2b 11 16 1e 63 d1 13 16 11 1e 11 09 91 13 23 11 1e 11 09 11 25 11 23 61 19 11 1d 58 61 11 2b 61 d2 9c 11 09 17 58 13 09 11 23 13 1d 11 09 11 27 32 a4 } 		$a_01_1 = {11 33 11 13 11 0f 11 13 91 9d 17 11 13 58 13 13 11 13 11 1f 32 ea } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}