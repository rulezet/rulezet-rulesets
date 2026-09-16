rule Trojan_Win32_ClipBanker_EB_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } 		$a_01_1 = {72 65 61 74 65 4d 75 74 65 78 57 } 		$a_01_2 = {62 00 63 00 31 00 71 00 } 		$a_03_3 = {68 00 02 00 00 6a 40 ff 15 ?? ?? ?? ?? 68 80 00 00 00 50 6a ff 89 04 37 8d 45 84 50 53 53 ff 15 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=5
 
}