rule Trojan_Win32_Trickbot_RTA_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 4c 68 b8 51 47 00 ff 75 ?? ff 55 ?? 85 c0 74 ?? 8b 45 ?? ff 30 50 ff 75 ?? 53 6a 01 53 ff 75 ?? ff 55 ?? 85 c0 0f 95 c0 eb ?? 32 c0 } 		$a_01_1 = {6a 3c 43 2a 31 72 58 26 45 35 39 49 71 43 32 } 	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}