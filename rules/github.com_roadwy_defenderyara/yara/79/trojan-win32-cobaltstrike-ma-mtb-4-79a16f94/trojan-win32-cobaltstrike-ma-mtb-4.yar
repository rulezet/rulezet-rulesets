rule Trojan_Win32_CobaltStrike_MA_MTB_4{
	meta:
		description = "Trojan:Win32/CobaltStrike.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 4a 01 89 08 8b 4c 90 90 [0-01] 89 ca c1 ea [0-01] 23 90 90 [0-02] 00 00 31 ca 89 d0 c1 e0 [0-01] 25 [0-04] 31 d0 89 c1 c1 e1 [0-01] 81 e1 [0-04] 31 c1 89 c8 c1 e8 [0-01] 31 c8 } 		$a_01_1 = {62 72 6f 6b 65 6e 20 70 69 70 65 } 		$a_01_2 = {63 6f 6e 6e 65 63 74 69 6f 6e 20 61 62 6f 72 74 65 64 } 		$a_01_3 = {6f 77 6e 65 72 20 64 65 61 64 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}