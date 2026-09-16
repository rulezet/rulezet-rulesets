rule Trojan_BAT_Remcos_AR_MTB_17{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 08 72 95 49 00 70 28 ?? ?? ?? 0a 72 b3 49 00 70 20 00 01 00 00 14 14 18 8d 10 00 00 01 25 16 06 11 08 9a a2 25 17 1f 10 } 		$a_01_1 = {50 00 65 00 6c 00 69 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}