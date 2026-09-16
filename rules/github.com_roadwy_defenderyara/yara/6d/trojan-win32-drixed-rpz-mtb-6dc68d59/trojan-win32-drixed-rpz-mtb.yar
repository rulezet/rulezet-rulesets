rule Trojan_Win32_Drixed_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Drixed.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 20 b9 02 00 00 00 e2 11 4a 4a 89 e8 50 8f 05 ?? ?? ?? ?? e9 31 fc ff ff c3 42 83 c2 07 29 c2 8d 05 ?? ?? ?? ?? 31 38 83 e8 09 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}