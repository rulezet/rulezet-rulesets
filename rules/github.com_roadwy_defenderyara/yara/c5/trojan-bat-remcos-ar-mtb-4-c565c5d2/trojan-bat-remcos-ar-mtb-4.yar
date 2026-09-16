rule Trojan_BAT_Remcos_AR_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 04 18 5b 07 11 04 18 6f 17 00 00 0a 1f 10 28 18 00 00 0a 9c 11 04 18 58 13 04 11 04 08 32 df } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}