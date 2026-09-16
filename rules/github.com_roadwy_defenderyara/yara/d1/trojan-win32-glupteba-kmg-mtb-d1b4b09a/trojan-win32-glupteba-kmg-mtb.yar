rule Trojan_Win32_Glupteba_KMG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 d0 c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? ?? ?? ?? ?? 45 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}