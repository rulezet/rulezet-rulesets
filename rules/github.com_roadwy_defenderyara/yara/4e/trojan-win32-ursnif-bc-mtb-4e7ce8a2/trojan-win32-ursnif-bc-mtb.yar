rule Trojan_Win32_Ursnif_BC_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 6f 72 6e } 		$a_81_1 = {46 69 74 73 65 63 6f 6e 64 } 		$a_81_2 = {50 61 73 74 70 75 74 } 		$a_02_3 = {c1 e0 06 33 c9 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 13 d1 [0-11] 83 c0 62 2b 05 ?? ?? ?? ?? 33 c9 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}