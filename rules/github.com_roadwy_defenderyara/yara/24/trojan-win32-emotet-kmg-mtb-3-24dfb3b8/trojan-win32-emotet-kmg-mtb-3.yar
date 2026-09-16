rule Trojan_Win32_Emotet_KMG_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d8 03 de 81 e3 ?? ?? ?? ?? 8b f3 8a 5c 34 ?? 88 5c 0c ?? 88 44 34 ?? 0f b6 5c 0c ?? 0f b6 c0 4d 03 d8 81 e3 ?? ?? ?? ?? 89 ac 24 ?? ?? ?? ?? 79 } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}