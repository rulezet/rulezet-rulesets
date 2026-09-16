rule Trojan_BAT_Scarsi_AS_MTB_2{
	meta:
		description = "Trojan:BAT/Scarsi.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f1 0b 2b f8 02 50 06 91 16 2c 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}