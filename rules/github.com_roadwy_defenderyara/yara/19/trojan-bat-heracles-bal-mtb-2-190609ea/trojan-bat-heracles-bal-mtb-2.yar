rule Trojan_BAT_Heracles_BAL_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 05 00 fe 0c 04 00 20 00 00 00 00 73 16 03 00 0a fe 0e 06 00 fe 0c 06 00 73 35 03 00 0a fe 0e 07 00 fe 0c 07 00 ?? ?? ?? 00 0a fe 0e 00 00 dd 39 00 00 00 fe 0c 07 00 39 09 00 00 00 fe 0c 07 00 ?? ?? 00 00 0a dc fe 0c 06 00 39 09 00 00 00 fe 0c 06 00 ?? ?? 00 00 0a dc fe 0c 05 00 39 09 00 00 00 fe 0c 05 00 ?? ?? 00 00 0a dc } 		$a_81_1 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}