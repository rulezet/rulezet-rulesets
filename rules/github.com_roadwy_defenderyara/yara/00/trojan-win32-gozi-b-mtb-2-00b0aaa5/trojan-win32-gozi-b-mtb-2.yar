rule Trojan_Win32_Gozi_B_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b d0 2b d7 83 c2 2e 89 15 ?? ?? ?? ?? 3b da 72 31 8b c2 0f af f1 2b c1 83 c3 26 69 ca 30 7b 00 00 03 d8 } 		$a_81_1 = {73 6c 65 65 70 2e 64 6c 6c } 		$a_81_2 = {45 67 67 62 61 6e 64 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}