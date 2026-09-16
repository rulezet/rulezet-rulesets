rule Trojan_BAT_Vidar_NV_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {1f 10 63 20 ?? ?? ?? 00 5f d2 6f ?? ?? ?? 0a 19 13 0b 38 ?? ?? ?? ff } 		$a_01_1 = {41 6e 79 44 65 73 6b 20 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } 		$a_01_2 = {4e 70 6e 61 64 46 42 61 61 78 6f 6d } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}