rule Trojan_Win32_Glupteba_KMG_MTB_7{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 75 05 0f 00 8b 1d ?? ?? ?? ?? 01 45 ?? ?? 5d ?? 8b 45 ?? 8a 14 08 a1 ?? ?? ?? ?? 88 14 08 } 		$a_02_1 = {30 04 16 42 3b d7 7c 90 09 05 00 e8 6b ff ff ff } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}