rule Trojan_Win32_Spynoon_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Spynoon.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 00 ff ff ff 40 89 45 ?? 8b 45 ?? 0f b6 84 05 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 0f b6 09 33 c8 8b 45 ?? 03 45 ?? 88 08 e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}