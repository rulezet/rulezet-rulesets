rule Trojan_Win32_Fareit_VP_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 8b 45 08 8b 00 83 45 fc ?? 8d 14 08 8a 4a 03 8a c1 8a d9 80 e1 ?? 24 ?? c0 e1 ?? 0a 0a c0 e0 ?? 0a 42 01 c0 e3 ?? 0a 5a 02 88 0c 3e 8b 4d fc 46 88 04 3e 8b 45 0c 46 88 1c 3e 46 3b 08 72 } 		$a_02_1 = {50 56 56 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1f 4f 79 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}