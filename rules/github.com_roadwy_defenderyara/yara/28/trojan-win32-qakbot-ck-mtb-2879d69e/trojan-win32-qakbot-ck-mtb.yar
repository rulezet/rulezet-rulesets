rule Trojan_Win32_Qakbot_CK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 10 8d 1c 0f 83 e3 ?? 8a 9b ?? ?? ?? 00 32 1c 16 42 88 19 3b 55 fc 72 e6 } 		$a_03_1 = {8b d1 83 e2 ?? 8a 92 ?? ?? ?? 00 32 14 08 74 07 41 3b ce 72 eb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}