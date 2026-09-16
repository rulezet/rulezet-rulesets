rule Trojan_Win32_Azorult_RT_MTB_21{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 89 4d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 55 ?? 03 d0 81 3d ?? ?? ?? ?? be 01 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}