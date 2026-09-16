rule Trojan_Win32_Qakbot_MF_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 50 0c 8b 48 70 8b ?? 94 00 00 00 88 1c 0a ff 40 70 8b 50 70 8b 88 94 00 00 00 8b 5c 24 28 88 1c 0a ff 40 70 8b 48 68 81 f1 ?? ?? ?? ?? 29 48 48 8b 88 80 00 00 00 09 88 c4 00 00 00 8b 88 a0 00 00 00 01 88 88 00 00 00 81 ff ?? ?? ?? ?? 0f 8c } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}