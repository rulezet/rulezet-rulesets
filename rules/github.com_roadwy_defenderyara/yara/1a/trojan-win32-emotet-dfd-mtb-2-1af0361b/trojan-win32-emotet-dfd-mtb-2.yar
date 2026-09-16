rule Trojan_Win32_Emotet_DFD_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 bd ?? ?? ?? ?? 0f b6 84 15 ?? ?? ?? ?? 8b 4d 10 03 8d ?? ?? ?? ?? 0f b6 11 33 d0 8b 45 10 03 85 90 1b 02 88 10 } 		$a_81_1 = {4c 6f 6b 56 37 44 35 6a 66 72 69 34 56 6a 48 50 64 31 6d 74 56 31 70 70 4e 4a 71 73 47 68 35 38 42 6a 67 6d 52 6f 42 44 4d 45 69 77 58 46 50 } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}