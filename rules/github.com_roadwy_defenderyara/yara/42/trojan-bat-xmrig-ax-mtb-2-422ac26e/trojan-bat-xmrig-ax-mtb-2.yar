rule Trojan_BAT_Xmrig_AX_MTB_2{
	meta:
		description = "Trojan:BAT/Xmrig.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 2c 1b 2d 1e 26 2b 2d 2b 32 2b 33 72 b5 00 00 70 7e 4c 00 00 0a 2b 2e 2b 33 18 2d 0d 26 dd 56 00 00 00 2b 2f 15 2c f6 2b dc 2b 2b 2b f0 28 ?? ?? ?? 06 2b cd 28 ?? ?? ?? 0a 2b cc 07 2b cb } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 36 00 37 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}