rule Trojan_Win32_SmokeLoader_RPX_MTB_9{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 44 24 20 8b 44 24 20 89 44 24 18 8b 4c 24 28 8b c7 d3 e8 89 44 24 14 8b 44 24 ?? 01 44 24 14 8b 44 24 14 33 44 24 18 31 44 24 10 8b 44 24 10 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}