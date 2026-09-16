rule Trojan_Win32_Qakbot_AO_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 41 cd 05 ee (3a|66 3b) ?? 90 13 e8 ?? ?? ?? ?? 59 (3a|66 3b) ?? 90 13 89 45 ?? 68 45 1b 13 42 (3a|66 3b) ?? 90 13 e8 ?? ?? ?? ?? 59 (3a|66 3b) ?? 90 13 89 45 ?? 68 43 ac 95 0e (3a|66 3b) } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}