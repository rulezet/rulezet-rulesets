rule Trojan_Win32_Gozi_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c1 18 00 00 00 89 45 fc 8b 45 fc 05 c0 00 00 00 05 e0 00 00 00 01 c8 89 45 f8 8b 45 f8 89 45 fc 8b 4d fc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}