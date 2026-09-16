rule Trojan_Win32_Stealc_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Stealc.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f6 8b c3 c1 e0 04 03 44 24 30 8b d3 c1 ea 05 03 54 24 28 8d 0c 2b 33 c1 89 54 24 14 89 44 24 10 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}