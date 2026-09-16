rule Trojan_Win32_Emotet_JG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.JG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f4 64 89 0d 00 00 00 00 59 5f 5f 5e 5b 8b e5 5d 51 c3 8b 4d [0-02] 33 cd e8 [0-04] e9 } 		$a_02_1 = {50 6a 00 6a 01 6a 00 8b 4d [0-02] 51 ff 15 [0-04] 85 c0 75 04 32 c0 eb 02 b0 01 8b 4d [0-02] 33 cd e8 [0-04] 8b e5 5d c3 } 		$a_80_2 = {43 72 79 70 74 45 6e 63 72 79 70 74 } 		$a_80_3 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}