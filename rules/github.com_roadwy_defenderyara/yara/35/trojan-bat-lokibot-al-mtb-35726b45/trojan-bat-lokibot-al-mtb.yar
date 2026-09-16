rule Trojan_BAT_Lokibot_AL_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 16 02 7b ?? 00 00 04 a2 09 17 02 7b ?? 00 00 04 a2 09 18 72 ?? 72 02 70 a2 11 04 6f ?? 00 00 0a 1a 9a 13 05 11 05 09 13 06 11 06 } 		$a_01_1 = {47 00 69 00 61 00 6f 00 44 00 69 00 65 00 6e 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}