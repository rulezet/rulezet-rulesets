rule Trojan_Win32_Emotet_CA_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.CA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c1 e1 1c c1 f9 1f 81 e1 32 88 db 0e 33 c1 } 		$a_01_1 = {c1 e1 1a c1 f9 1f 81 e1 c8 20 6e 3b 33 c1 } 		$a_01_2 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 74 e8 8b 41 fc 84 c0 74 32 } 		$a_01_3 = {ff e0 5f 5e 5b c9 c2 08 00 58 59 87 04 24 ff e0 58 59 87 04 24 ff e0 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}