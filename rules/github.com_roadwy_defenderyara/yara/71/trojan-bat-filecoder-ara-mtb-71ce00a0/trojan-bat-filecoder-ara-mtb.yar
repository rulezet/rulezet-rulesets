rule Trojan_BAT_FileCoder_ARA_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {2e 46 75 63 6b 4f 66 66 } 		$a_80_1 = {5c 55 72 46 69 6c 65 2e 54 58 54 } 		$a_80_2 = {59 6f 75 20 68 61 76 65 20 42 65 65 6e 20 48 61 63 6b 33 64 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}