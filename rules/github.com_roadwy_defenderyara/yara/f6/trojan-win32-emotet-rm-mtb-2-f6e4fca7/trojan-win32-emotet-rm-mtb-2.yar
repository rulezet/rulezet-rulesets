rule Trojan_Win32_Emotet_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {73 26 70 57 31 56 42 56 4d 62 61 38 45 40 72 25 55 56 5f 6d 6a 31 47 24 32 59 4f 4c 53 51 2b 4c 6a 43 } 		$a_03_1 = {81 c9 00 10 00 00 51 8b 45 ?? 50 6a 00 6a ff ff 15 ?? ?? ?? ?? 89 45 } 	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}