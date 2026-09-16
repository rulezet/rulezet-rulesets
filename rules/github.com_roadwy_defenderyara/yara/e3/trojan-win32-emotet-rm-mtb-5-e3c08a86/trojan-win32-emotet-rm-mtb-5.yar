rule Trojan_Win32_Emotet_RM_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b f9 57 56 6a 00 6a ff ff 15 ?? ?? ?? ?? e9 } 		$a_80_1 = {6d 5f 64 23 35 37 25 35 5a 4e 53 45 31 6e 49 67 69 31 68 26 41 39 3f 39 4a 25 77 66 6f 50 46 6e 72 79 59 40 4a 57 55 40 58 2b 5f 70 78 2a 64 4c 70 25 56 78 43 5f 6f 64 51 3f 32 39 6a 25 76 46 76 39 69 51 5f 53 } 	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}