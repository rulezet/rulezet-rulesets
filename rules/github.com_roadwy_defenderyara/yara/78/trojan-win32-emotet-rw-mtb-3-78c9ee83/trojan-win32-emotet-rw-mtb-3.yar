rule Trojan_Win32_Emotet_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {5e 35 23 43 61 73 56 30 24 34 26 4e 47 62 45 54 4b 53 24 35 3f 33 51 35 45 49 4a 42 78 74 75 67 6b 35 6a 48 79 53 53 53 67 31 63 45 38 39 74 61 3c 4b 78 51 71 70 32 6b 50 4b 72 46 71 32 56 56 7a 6c 41 24 64 79 32 77 67 77 39 7a 75 32 78 62 3c 26 6a 4a } 		$a_03_1 = {0b e9 55 57 6a 00 6a ff ff 15 ?? ?? ?? ?? e9 } 	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}