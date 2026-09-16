rule Trojan_Win32_Emotet_GKM_MTB_16{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 be 33 06 01 00 f7 f6 41 81 f9 33 06 01 00 8b f2 8a 44 34 ?? 88 44 0c ?? 88 5c 34 ?? 72 } 		$a_02_1 = {33 d2 be 53 88 00 00 f7 f6 41 81 f9 53 88 00 00 8b f2 8a 44 34 ?? 88 44 0c ?? 88 5c 34 ?? 72 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}