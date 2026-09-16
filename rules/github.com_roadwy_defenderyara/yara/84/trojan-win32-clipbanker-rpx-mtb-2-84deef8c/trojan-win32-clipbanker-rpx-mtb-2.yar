rule Trojan_Win32_ClipBanker_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 56 8b 51 f8 89 54 24 2c ff d3 8b 44 24 28 83 f8 22 8b 44 24 14 0f 85 60 02 00 00 80 38 54 0f 85 52 02 00 00 8b 4c 24 18 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}