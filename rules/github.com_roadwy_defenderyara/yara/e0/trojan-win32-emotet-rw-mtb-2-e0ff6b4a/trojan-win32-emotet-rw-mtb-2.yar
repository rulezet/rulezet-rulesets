rule Trojan_Win32_Emotet_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {5f 23 69 40 59 52 21 49 5f 70 44 31 56 50 52 5a 33 79 69 24 50 54 3c 34 79 24 69 49 23 79 39 23 74 38 29 58 41 34 50 39 } 		$a_03_1 = {83 c4 04 f7 d8 50 ff 15 ?? ?? ?? ?? 89 45 ?? eb ?? 6a 40 68 00 30 00 00 } 	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}