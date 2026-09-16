rule Trojan_Win32_Emotet_PX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d0 8b 45 ?? 0f b6 14 10 8b 45 ?? 0f b6 0c 08 33 ca } 		$a_03_1 = {2b c1 03 05 ?? ?? ?? ?? 8b 55 ?? 2b c2 8b 4d ?? 8b 55 ?? 88 14 01 e9 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}