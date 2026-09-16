rule Trojan_Win32_TrickBot_GE_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 44 24 1f 0f b6 f0 8a 44 24 1e 0f b6 f8 89 f8 09 f0 88 44 24 1e c7 44 24 40 91 00 00 00 8a 44 24 17 0f b6 f0 8a 44 24 1e 0f b6 f8 89 f8 31 f0 88 44 24 1e } 		$a_81_1 = {54 79 72 65 44 6f 6b 67 57 } 	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}