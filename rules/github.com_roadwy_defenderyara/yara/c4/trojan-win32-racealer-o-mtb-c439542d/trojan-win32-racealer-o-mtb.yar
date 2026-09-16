rule Trojan_Win32_Racealer_O_MTB{
	meta:
		description = "Trojan:Win32/Racealer.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {b8 36 23 01 00 01 45 fc [0-08] 03 55 08 8b 45 fc 03 45 08 8a 08 88 0a } 		$a_00_1 = {c7 45 fc 04 00 00 00 8b 45 0c 8b 4d fc d3 e0 8b 4d 08 89 01 } 		$a_00_2 = {8b 45 08 8b 08 33 4d 0c 8b 55 08 89 0a } 		$a_00_3 = {8b 45 08 8b 4d 0c 33 08 8b 55 08 89 0a } 		$a_03_4 = {83 e9 14 88 0d ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 83 ea 14 88 15 ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 83 e8 14 a2 ?? ?? ?? ?? 0f be 0d ?? ?? ?? ?? 83 e9 0a } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}