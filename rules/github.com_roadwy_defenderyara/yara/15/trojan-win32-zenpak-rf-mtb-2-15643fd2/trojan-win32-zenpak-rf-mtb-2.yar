rule Trojan_Win32_Zenpak_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 c3 83 f2 02 83 c2 09 83 f0 08 01 1d ?? ?? ?? ?? 40 89 3d ?? ?? ?? ?? b9 02 00 00 00 e2 ce } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}