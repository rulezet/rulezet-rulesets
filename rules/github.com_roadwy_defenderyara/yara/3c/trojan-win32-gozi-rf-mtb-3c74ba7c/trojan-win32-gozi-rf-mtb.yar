rule Trojan_Win32_Gozi_RF_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d d0 89 4d f0 8b 55 cc 89 55 f8 8b 45 cc 89 45 e0 8b 4d e0 8b 11 33 55 f0 8b 45 e0 89 10 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}