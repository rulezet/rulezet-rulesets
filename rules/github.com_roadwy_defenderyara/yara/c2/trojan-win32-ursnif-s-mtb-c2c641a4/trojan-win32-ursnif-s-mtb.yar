rule Trojan_Win32_Ursnif_S_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e4 b9 ?? ?? ?? ?? 89 45 e0 31 d2 f7 f1 8a 1c 15 ?? ?? ?? ?? 8b 4d ec 8b 55 e0 8a 3c 11 28 df 8b 75 e8 88 3c 16 83 c2 01 8b 7d f0 39 fa 89 55 e4 74 c4 eb ca } 		$a_03_1 = {31 c9 8d 55 d6 89 45 a0 89 55 9c 89 4d 98 8b 45 98 8a 0c 05 ?? ?? ?? ?? 8a 14 05 ?? ?? ?? ?? 28 ca 88 54 05 d6 83 c0 01 83 f8 14 89 45 98 75 de } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}