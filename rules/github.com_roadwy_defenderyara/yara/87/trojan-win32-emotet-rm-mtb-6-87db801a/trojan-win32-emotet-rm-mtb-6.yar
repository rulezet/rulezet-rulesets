rule Trojan_Win32_Emotet_RM_MTB_6{
	meta:
		description = "Trojan:Win32/Emotet.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {3c 4d 51 45 75 49 4f 77 47 6c 32 44 7a 23 57 48 51 45 52 34 51 4e 5e 36 24 55 46 23 44 37 59 28 24 28 42 57 6f 75 48 36 71 3c 64 24 77 6c 36 29 51 4c 67 6d 62 39 58 53 4b 77 75 3c 70 6d 23 72 35 4f 3f 41 45 } 		$a_03_1 = {81 c9 00 10 00 00 51 56 53 6a ff ff 15 ?? ?? ?? ?? eb ?? 6a 40 68 00 30 00 00 } 	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}