rule Trojan_Win32_UrSnif_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/UrSnif.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 d2 74 01 ea 31 1a 81 ee 01 00 00 00 68 21 34 a3 ec 58 81 c2 04 00 00 00 01 f8 39 ca 75 e1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}