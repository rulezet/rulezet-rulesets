rule Trojan_Win32_Emotet_AD_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 24 0a 8b 54 24 ?? 8a 5c 24 ?? c7 44 24 ?? 00 00 00 00 c7 44 24 ?? 00 00 00 00 01 ce b7 31 28 df 30 f8 00 c4 } 		$a_02_1 = {8b 44 24 04 8a 4c 24 ?? 88 08 8d 65 ?? 5e 5f 5b 5d } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}