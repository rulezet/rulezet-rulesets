rule Trojan_BAT_Tedy_AT_MTB{
	meta:
		description = "Trojan:BAT/Tedy.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 6a 0a 2b 05 06 17 6a 58 0a 06 04 34 0c 02 06 58 02 06 58 47 03 61 52 2b eb } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}