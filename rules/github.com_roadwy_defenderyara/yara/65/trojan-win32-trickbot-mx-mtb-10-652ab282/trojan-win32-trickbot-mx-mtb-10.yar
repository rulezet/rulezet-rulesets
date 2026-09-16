rule Trojan_Win32_Trickbot_MX_MTB_10{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 4f ff 4e 0f 85 } 		$a_80_1 = {67 41 42 75 70 61 65 56 39 7a 61 77 61 68 6f 52 45 4f 35 32 32 32 56 66 33 31 41 36 4e 37 69 50 41 45 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}