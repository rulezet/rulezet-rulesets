rule Trojan_BAT_Remcos_ARC_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 04 00 00 04 28 32 00 00 0a 04 6f 33 00 00 0a 6f 34 00 00 0a 0a 7e 03 00 00 04 06 6f 35 00 00 0a 00 7e 03 00 00 04 18 6f 36 00 00 0a 00 02 03 05 28 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}