rule Trojan_Win32_Emotet_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a d9 03 de 81 e3 ?? ?? ?? ?? 8b f3 8a 5c 34 ?? 88 5c 14 ?? 88 4c 34 ?? 0f b6 5c 14 ?? 0f b6 c9 03 d9 81 e3 ?? ?? ?? ?? 79 } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}