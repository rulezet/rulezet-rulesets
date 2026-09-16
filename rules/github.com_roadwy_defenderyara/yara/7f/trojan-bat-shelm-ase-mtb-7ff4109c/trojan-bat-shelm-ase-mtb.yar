rule Trojan_BAT_Shelm_ASE_MTB{
	meta:
		description = "Trojan:BAT/Shelm.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 16 2b 15 07 11 16 07 11 16 91 20 dc 00 00 00 61 d2 9c 11 16 17 58 13 16 11 16 07 8e 69 32 e4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}