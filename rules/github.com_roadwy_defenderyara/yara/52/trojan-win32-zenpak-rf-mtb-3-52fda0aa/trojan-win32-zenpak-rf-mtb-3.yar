rule Trojan_Win32_Zenpak_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {90 55 89 e5 50 8b 45 08 31 c9 81 c1 18 00 00 00 89 45 fc 8b 45 fc 05 d0 00 00 00 05 e0 00 00 00 01 c8 89 45 fc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}