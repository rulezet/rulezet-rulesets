rule Trojan_Win32_Lokibot_D_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 01 00 00 00 90 90 90 90 [0-10] 81 fb ?? ?? ?? ?? 75 } 		$a_03_1 = {4b 75 f8 e8 ?? ?? ?? ?? 90 90 90 90 bb ?? ?? ?? 00 e8 ?? ?? ?? ?? 4b 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}