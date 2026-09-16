rule Trojan_Win32_Emotet_GD_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c0 03 c2 99 f7 fb 0f b6 44 14 ?? 32 44 2e ?? 83 6c 24 [0-10] 88 46 } 		$a_81_1 = {6e 56 63 68 6d 4a 68 77 52 52 25 21 40 4a 69 7a 4f 39 72 5a 6d 43 4a 54 55 6f 6b 24 58 35 54 26 33 4f 40 48 65 63 75 31 34 41 4a 21 70 68 52 68 59 6a } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}