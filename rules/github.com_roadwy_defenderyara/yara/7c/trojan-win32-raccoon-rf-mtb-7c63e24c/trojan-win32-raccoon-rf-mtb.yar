rule Trojan_Win32_Raccoon_RF_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 d8 31 18 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}