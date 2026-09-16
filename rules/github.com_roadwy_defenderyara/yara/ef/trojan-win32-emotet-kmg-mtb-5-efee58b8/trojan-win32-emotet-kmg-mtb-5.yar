rule Trojan_Win32_Emotet_KMG_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {99 8b ce f7 f9 0f b6 04 2f 8a 0c 3a 88 0c 2f 88 04 3a 0f b6 04 2f 89 54 24 1c 0f b6 14 3a } 		$a_02_1 = {f6 d2 f6 d1 0a d1 22 d3 88 10 40 89 44 24 ?? 8b 44 24 ?? 48 89 44 24 ?? 0f 85 } 		$a_02_2 = {f6 d2 0a d8 8b 44 24 ?? f6 d1 0a d1 22 d3 88 10 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}