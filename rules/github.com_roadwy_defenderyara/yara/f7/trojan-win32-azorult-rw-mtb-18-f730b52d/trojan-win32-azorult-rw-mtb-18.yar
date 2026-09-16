rule Trojan_Win32_Azorult_RW_MTB_18{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b fe 8b c7 c1 e0 04 03 45 ?? 03 cf 81 3d ?? ?? ?? ?? be 01 00 00 } 		$a_03_1 = {c1 ea 05 03 55 ?? 50 8d 4d ?? 51 c7 05 ?? ?? ?? ?? b4 02 d7 cb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}