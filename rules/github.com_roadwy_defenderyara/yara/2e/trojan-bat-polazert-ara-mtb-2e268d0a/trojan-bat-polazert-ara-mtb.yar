rule Trojan_BAT_Polazert_ARA_MTB{
	meta:
		description = "Trojan:BAT/Polazert.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 47 06 09 91 61 d2 52 09 17 58 06 8e 69 32 04 16 0d 2b 04 09 17 58 0d 08 17 58 0c 08 07 8e 69 32 d7 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}