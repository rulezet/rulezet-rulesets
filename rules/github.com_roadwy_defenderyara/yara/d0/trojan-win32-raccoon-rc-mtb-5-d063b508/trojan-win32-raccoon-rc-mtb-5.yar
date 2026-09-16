rule Trojan_Win32_Raccoon_RC_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 4d ?? 8b c6 d3 e0 [0-15] 03 c6 89 45 ?? 8b c6 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}