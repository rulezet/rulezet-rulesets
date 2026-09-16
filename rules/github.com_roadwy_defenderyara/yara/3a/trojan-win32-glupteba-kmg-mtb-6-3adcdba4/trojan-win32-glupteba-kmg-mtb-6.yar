rule Trojan_Win32_Glupteba_KMG_MTB_6{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 0c 10 8b 0d ?? ?? ?? ?? 40 3b c1 72 } 		$a_02_1 = {c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? ?? ?? ?? 01 45 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}