rule Trojan_BAT_AsyncRAT_ARA_MTB_5{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 20 ff 00 00 00 5f 2b 1d 03 6f ?? ?? ?? 0a 0c 2b 17 08 06 08 06 93 02 7b ?? ?? ?? 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a 16 2f 02 2b 05 2b dd 0a 2b c8 } 		$a_01_1 = {57 69 6e 64 6f 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}