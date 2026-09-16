rule Trojan_Win32_Trickbot_RM_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 db 8a 1c 02 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d8 03 ?? ?? ?? ?? ?? 8b ?? ?? 8a 04 0a 32 c3 8b ?? ?? 8b 11 8b ?? ?? 88 04 11 e9 } 		$a_81_1 = {44 48 4b 57 25 61 29 54 45 50 77 78 25 4b 78 61 76 21 51 78 72 59 41 77 74 53 42 51 6a 6e 4e 53 40 3f 68 4a 46 49 4e 4c 50 62 62 76 6d 37 43 4e 21 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}