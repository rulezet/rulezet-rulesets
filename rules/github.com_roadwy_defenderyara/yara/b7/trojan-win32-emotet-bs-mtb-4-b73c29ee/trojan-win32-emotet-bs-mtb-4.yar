rule Trojan_Win32_Emotet_BS_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {03 c3 99 f7 f9 0f b6 04 37 8b da 8a 14 33 88 14 37 88 04 33 0f b6 0c 33 0f b6 04 37 03 c1 } 		$a_02_1 = {02 d2 8a cc c0 e9 04 02 d2 0a ca 88 0e 8a 4c 24 ?? 8a d1 8a c4 c0 e0 04 83 c6 01 c0 ea 02 0a d0 c0 e1 06 0a 4c 24 ?? 88 16 83 c6 01 88 0e } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}