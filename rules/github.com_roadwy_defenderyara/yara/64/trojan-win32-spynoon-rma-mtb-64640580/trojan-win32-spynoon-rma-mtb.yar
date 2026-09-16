rule Trojan_Win32_Spynoon_RMA_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 f6 1d 7e c4 b0 f7 de 81 c6 41 6b 9a 64 3b 73 ?? 0f 95 c1 89 8d ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? 8b 0e 03 4f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}