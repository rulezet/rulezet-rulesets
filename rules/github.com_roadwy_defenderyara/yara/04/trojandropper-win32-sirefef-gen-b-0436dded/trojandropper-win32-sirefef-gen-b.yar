rule TrojanDropper_Win32_Sirefef_gen_B{
	meta:
		description = "TrojanDropper:Win32/Sirefef.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 bc 94 07 00 00 8b 45 e4 8b 4d 08 03 0c b8 89 4d ec 8b 45 ec } 		$a_03_1 = {8b 4d b8 8b 55 bc 33 c0 81 c7 ?? ?? ?? ?? 83 d0 ff } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}