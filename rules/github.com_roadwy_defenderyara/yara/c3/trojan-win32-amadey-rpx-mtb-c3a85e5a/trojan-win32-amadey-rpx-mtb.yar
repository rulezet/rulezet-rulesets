rule Trojan_Win32_Amadey_RPX_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 da cc 00 00 00 81 da aa 00 00 00 c1 c2 b2 83 c3 6e c1 c7 ee f7 d3 c1 df 2d 8b 7d 08 f6 17 80 07 9f fe 07 47 e2 f6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}