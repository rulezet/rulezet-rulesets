rule Trojan_BAT_Heracles_NH_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 03 0c 2b f5 2a 06 6f ?? ?? 00 06 28 ?? ?? 00 0a 28 ?? ?? 00 0a 2a } 		$a_01_1 = {4e 6a 72 67 61 6f 73 68 78 78 6f 6f 69 6b 73 72 67 78 74 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}