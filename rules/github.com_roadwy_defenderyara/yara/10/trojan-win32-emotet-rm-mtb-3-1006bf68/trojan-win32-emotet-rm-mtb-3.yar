rule Trojan_Win32_Emotet_RM_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {58 3e 4a 54 51 28 44 6b 54 25 78 6b 48 5e 38 4a 70 52 40 40 38 77 58 6a 79 68 5a 6f 79 44 45 46 37 67 23 31 6b 4c 44 70 6d 32 33 70 41 49 32 75 6c 77 77 79 65 56 } 		$a_03_1 = {68 00 30 00 00 8b 45 ?? 50 6a 00 6a ff ff } 	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}