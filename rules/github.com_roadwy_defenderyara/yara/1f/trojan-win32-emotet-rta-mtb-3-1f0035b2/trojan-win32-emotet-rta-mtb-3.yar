rule Trojan_Win32_Emotet_RTA_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b c1 50 56 6a 00 6a ff ff 15 ?? ?? ?? ?? e9 } 		$a_03_1 = {03 c5 03 44 24 ?? 8b 6c 24 ?? 03 44 24 ?? 83 c5 01 03 44 24 ?? 89 6c 24 ?? 0f b6 14 10 8b 44 24 ?? 30 54 28 ?? 3b ac 24 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}