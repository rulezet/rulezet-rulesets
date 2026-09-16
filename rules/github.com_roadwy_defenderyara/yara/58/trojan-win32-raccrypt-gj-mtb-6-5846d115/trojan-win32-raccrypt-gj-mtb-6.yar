rule Trojan_Win32_Raccrypt_GJ_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {36 23 01 00 90 02 06 88 0c 32 8b e5 5d c3 } 		$a_02_1 = {b4 02 d7 cb [0-06] c7 05 ?? ?? ?? ?? ff ff ff ff 89 [0-06] e8 ?? ?? ?? ?? 8b [0-03] 29 [0-03] 68 ?? ?? ?? ?? 8d [0-03] 52 e8 [0-07] 0f 85 } 		$a_02_2 = {55 8b ec 8b 45 08 8b 4d 0c 31 08 5d c2 ?? 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10) >=11
 
}