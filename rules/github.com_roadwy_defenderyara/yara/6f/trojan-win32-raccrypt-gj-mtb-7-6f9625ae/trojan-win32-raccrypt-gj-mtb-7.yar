rule Trojan_Win32_Raccrypt_GJ_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 94 31 36 23 01 00 88 ?? ?? 30 81 c4 ?? ?? ?? ?? c3 } 		$a_00_1 = {36 23 01 00 88 0c 32 8b e5 5d c3 } 		$a_02_2 = {b4 02 d7 cb [0-06] c7 05 ?? ?? ?? ?? ff ff ff ff 89 [0-03] e8 ?? ?? ?? ?? 8b ca e8 ?? ?? ?? ?? 8b [0-03] 29 [0-03] 8d [0-03] e8 ?? ?? ?? ?? 4f 8b [0-03] 0f 85 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*10) >=11
 
}