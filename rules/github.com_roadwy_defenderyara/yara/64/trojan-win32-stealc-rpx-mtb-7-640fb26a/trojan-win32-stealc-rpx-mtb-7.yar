rule Trojan_Win32_Stealc_RPX_MTB_7{
	meta:
		description = "Trojan:Win32/Stealc.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 8b 15 30 00 00 00 81 c2 00 0f 00 00 89 55 e8 b8 04 00 00 00 d1 e0 8b 4d e8 8b 94 05 e0 fe ff ff 89 11 b8 04 00 00 00 6b c8 03 8b 55 e8 8b 84 0d e0 fe ff ff 89 42 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}