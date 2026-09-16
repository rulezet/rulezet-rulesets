rule Trojan_Win32_Qakbot_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {33 c8 8b 45 08 eb ?? 0f b6 08 8b 45 fc eb ?? 40 89 45 fc eb } 		$a_03_1 = {8b 45 08 03 45 fc eb ?? 55 8b ec eb ?? 99 f7 7d 14 eb ?? 8b 45 10 0f b6 04 10 eb c7 03 45 fc 88 08 eb } 		$a_01_2 = {61 6f 72 62 69 73 5f 73 79 6e 74 68 65 73 69 73 5f 74 72 61 63 6b 6f 6e 6c 79 } 		$a_01_3 = {61 6f 72 62 69 73 5f 73 79 6e 74 68 65 73 69 73 5f 62 6c 6f 63 6b 69 6e } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}