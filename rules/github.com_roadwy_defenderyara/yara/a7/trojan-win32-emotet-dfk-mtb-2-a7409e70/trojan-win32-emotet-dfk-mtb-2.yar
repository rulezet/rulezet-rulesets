rule Trojan_Win32_Emotet_DFK_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8a 94 04 ?? ?? ?? ?? 8b c2 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 9c 14 90 1b 00 8b 54 24 18 32 1a } 		$a_81_1 = {36 67 33 74 6d 77 4a 4f 4d 49 55 4e 6f 71 50 73 4a 74 5a 6a 54 34 53 57 70 55 48 32 6f 59 6a 57 30 6d 6f 75 7a 58 6d 31 63 79 70 46 61 } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}