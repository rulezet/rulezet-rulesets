rule Trojan_BAT_KillMBR_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 10 00 00 13 04 11 04 17 da 17 d6 8d ?? ?? ?? 01 0c 16 6a 0d 09 20 ?? ?? ?? 00 6a 31 02 2b 2c 06 08 08 8e b7 b8 08 8e b7 b8 13 05 12 05 7e ?? ?? ?? 0a 28 ?? ?? ?? 06 26 07 08 16 08 8e b7 6f ?? ?? ?? 0a 09 11 04 6a d6 0d 2b c9 } 		$a_80_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } 	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}