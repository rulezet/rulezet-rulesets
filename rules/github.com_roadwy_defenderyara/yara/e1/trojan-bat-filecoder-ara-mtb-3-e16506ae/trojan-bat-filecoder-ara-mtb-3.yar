rule Trojan_BAT_FileCoder_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/FileCoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 9a 0c 00 08 28 ?? ?? ?? 06 00 08 28 ?? ?? ?? 06 00 00 07 17 58 0b 07 06 8e 69 32 e2 } 		$a_80_1 = {5c 4c 6f 63 6b 42 49 54 5c 73 79 73 74 65 6d 49 44 } 	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}