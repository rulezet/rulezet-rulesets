rule Trojan_Win32_Sakurel_C_dha_2{
	meta:
		description = "Trojan:Win32/Sakurel.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 02 8a 01 84 c0 74 08 3c ?? 74 04 34 ?? 88 01 42 3b 55 0c 7c } 		$a_03_1 = {ff 74 24 10 b2 54 e8 ?? ?? ?? ?? ff 74 24 14 80 c2 f8 8b f0 e8 ?? ?? ?? ?? ff 74 24 18 b2 45 8b d8 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}