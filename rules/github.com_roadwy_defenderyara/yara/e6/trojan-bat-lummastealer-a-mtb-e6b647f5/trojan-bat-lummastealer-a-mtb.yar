rule Trojan_BAT_LummaStealer_A_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 ff a2 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 b2 00 00 00 81 01 00 00 e1 05 00 00 f9 06 00 00 d5 05 } 		$a_01_1 = {54 6f 41 72 72 61 79 } 		$a_01_2 = {4f 70 65 6e 53 75 62 4b 65 79 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}