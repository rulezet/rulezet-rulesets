rule Trojan_Win32_Trickbot_MX_MTB_17{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 14 5b 53 51 48 8b c6 48 ff c6 48 8b 0f 48 8b 00 48 33 c8 58 88 0f 48 ff c7 48 ff cb 48 8b c8 75 } 		$a_80_1 = {53 6c 65 65 70 } 		$a_80_2 = {74 65 6d 70 6c 2e 64 6c 6c } 		$a_80_3 = {46 72 65 65 42 75 66 66 65 72 } 		$a_80_4 = {52 65 6c 65 61 73 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}