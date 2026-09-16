rule Trojan_BAT_Remcos_ARS_MTB_6{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 7e 01 00 00 04 07 6f ?? ?? ?? 0a 00 7e 01 00 00 04 18 6f ?? ?? ?? 0a 00 02 05 03 04 16 28 ?? ?? ?? 06 0c 2b 00 08 2a } 		$a_01_1 = {73 61 6c 61 6d 61 6e 63 61 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}