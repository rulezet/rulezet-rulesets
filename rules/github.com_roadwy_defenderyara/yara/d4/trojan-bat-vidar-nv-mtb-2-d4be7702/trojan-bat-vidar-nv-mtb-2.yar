rule Trojan_BAT_Vidar_NV_MTB_2{
	meta:
		description = "Trojan:BAT/Vidar.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {d0 8f 02 00 04 28 ?? ?? 00 0a 6f ?? ?? 00 0a 07 1f 10 8d ?? ?? 00 01 25 d0 ?? ?? 00 04 28 ?? ?? 00 0a 6f ?? ?? 00 0a 06 07 6f ?? ?? 00 0a 17 73 ?? ?? 00 0a 0c 08 02 16 02 8e 69 6f ?? ?? 00 0a } 		$a_01_1 = {69 6e 67 65 6e 69 6f 75 73 5f 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 5f 73 6f 6c 75 74 69 6f 6e } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}