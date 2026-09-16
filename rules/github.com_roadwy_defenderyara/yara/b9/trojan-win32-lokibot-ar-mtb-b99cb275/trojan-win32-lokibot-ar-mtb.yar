rule Trojan_Win32_Lokibot_AR_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {29 d2 03 11 bb ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 4a 39 1a eb } 		$a_03_1 = {89 d3 8b 0f 31 f1 [0-05] 11 0c 18 } 		$a_01_2 = {46 ff 37 59 31 f1 39 c1 75 } 		$a_01_3 = {01 c2 8b 1a ff d3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}