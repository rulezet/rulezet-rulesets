rule Trojan_Win32_TrickBot_GM_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 99 b9 ?? ?? ?? ?? f7 f9 8b 45 08 0f be 0c ?? 8b 55 0c 03 55 f8 0f b6 02 33 c1 8b 4d 0c 03 4d f8 88 01 8b 55 fc 83 c2 01 89 55 fc } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}