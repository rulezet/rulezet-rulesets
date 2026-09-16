rule Trojan_Win32_Lokibot_AN_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {01 f3 0f 6e c0 0f 6e 0b 0f ef c1 51 0f 7e c1 eb } 		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 08 89 c8 eb } 		$a_03_2 = {66 31 0c 18 81 fb ?? ?? 00 00 7d 05 83 c3 02 eb } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}