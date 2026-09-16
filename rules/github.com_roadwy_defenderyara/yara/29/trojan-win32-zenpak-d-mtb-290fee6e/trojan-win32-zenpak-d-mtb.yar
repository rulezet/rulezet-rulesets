rule Trojan_Win32_Zenpak_D_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 8b 4d e4 8b 55 e0 01 ca 89 15 ?? ?? ?? ?? 8b 4d ec 8a 1c 01 8b 55 e8 88 1c 02 05 01 00 00 00 8b 75 f0 39 f0 89 45 d8 74 19 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}