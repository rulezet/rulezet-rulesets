rule Trojan_Win32_Raccoon_RF_MTB_9{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 44 24 ?? 38 dd 96 53 8b c6 [0-40] 8b d6 d3 ea 03 d5 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 31 44 24 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}