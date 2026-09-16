rule Trojan_Win32_Qakbot_BS_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f 11 44 24 04 8d 44 24 04 50 51 01 f9 ff d1 85 ff 74 ?? b9 ?? ?? ?? ?? 03 4c 24 08 6a 40 51 8b 7c 24 44 ff 77 20 6a 00 ff d0 } 		$a_00_1 = {44 72 61 77 54 68 65 6d 65 49 63 6f 6e } 		$a_00_2 = {6d 66 69 78 61 75 74 6f 75 74 69 6c 34 2e 64 6c 6c } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}