rule Trojan_Win32_Lokibot_AZ_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 29 c9 eb 06 90 05 10 01 00 85 c0 eb 90 05 10 01 00 43 eb 90 05 10 01 00 66 81 fa ?? ?? eb 90 05 10 01 00 0b 0f eb 90 05 10 01 00 66 81 fb ?? ?? eb 90 05 10 01 00 31 d9 eb 90 05 10 01 00 85 c0 eb 90 05 10 01 00 39 c1 eb 90 05 10 01 00 75 9c 66 81 fa ?? ?? eb } 		$a_03_1 = {29 c9 eb 01 [0-10] 43 eb [0-10] 0b 0f eb [0-10] 31 d9 eb [0-10] 39 c1 75 ?? eb [0-10] eb [0-10] 89 de eb [0-10] eb [0-10] 48 b9 ?? ?? ?? 00 eb [0-10] eb [0-10] 81 f1 ?? ?? ?? 00 eb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}