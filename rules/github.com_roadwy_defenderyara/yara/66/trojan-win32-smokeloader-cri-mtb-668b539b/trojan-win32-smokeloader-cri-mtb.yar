rule Trojan_Win32_SmokeLoader_CRI_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 03 c6 89 45 e8 03 55 d4 8b 45 e8 31 45 fc 31 55 fc 2b 7d fc 8b 45 ?? 29 45 f8 ff 4d e4 0f 85 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}