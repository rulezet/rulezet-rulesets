rule Trojan_Win32_TrickBot_DB_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8d 46 01 f7 35 ?? ?? ?? ?? 43 8b f2 8a 04 0e 88 45 ff 0f b6 c0 03 c7 33 d2 f7 35 ?? ?? ?? ?? 8b fa 0f b6 04 0f 8a 55 ff 88 04 0e 88 14 0f 0f b6 04 0e 0f b6 d2 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 45 0c 0f b6 14 0a 02 15 ?? ?? ?? ?? 30 54 03 ff } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}