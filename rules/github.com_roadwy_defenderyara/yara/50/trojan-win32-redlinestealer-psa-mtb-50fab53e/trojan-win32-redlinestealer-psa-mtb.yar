rule Trojan_Win32_RedlineStealer_PSA_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.PSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 0d ?? ?? ?? ?? ff c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 e4 01 45 0c 8b 45 0c 33 45 f8 33 c8 89 4d ec 8b 45 ec } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}