rule Trojan_Win32_Azorult_RF_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2e ce 50 91 03 45 ?? 33 c7 83 3d ?? ?? ?? ?? 27 89 45 ?? 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}