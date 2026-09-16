rule Trojan_BAT_Stealc_RPX_MTB{
	meta:
		description = "Trojan:BAT/Stealc.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {17 13 07 16 13 08 2b 18 02 11 06 11 08 58 91 07 11 08 91 2e 05 16 13 07 2b 0d 11 08 17 58 13 08 11 08 07 8e 69 32 e1 } 		$a_01_1 = {4c 00 6f 00 76 00 65 00 20 00 68 00 61 00 73 00 20 00 64 00 69 00 66 00 66 00 65 00 72 00 65 00 6e 00 74 00 20 00 74 00 79 00 70 00 65 00 73 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}