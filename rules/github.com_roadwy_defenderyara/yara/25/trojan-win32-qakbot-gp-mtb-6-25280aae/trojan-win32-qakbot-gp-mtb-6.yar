rule Trojan_Win32_Qakbot_GP_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {b8 4c 66 44 00 cc cc ff 15 ?? ?? ?? ?? 68 dc 0f 07 10 c3 } 		$a_00_1 = {c0 c0 07 68 09 28 07 10 c3 } 		$a_00_2 = {32 c1 68 4b 0f 07 10 c3 } 		$a_00_3 = {68 ea 0e 00 00 68 a7 e7 06 10 68 a7 e7 06 10 b8 8c fa 06 10 ff d0 } 		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_80_4  & 1)*1) >=21
 
}