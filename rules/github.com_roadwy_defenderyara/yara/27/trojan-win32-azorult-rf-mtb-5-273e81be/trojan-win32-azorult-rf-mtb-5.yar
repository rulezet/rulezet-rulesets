rule Trojan_Win32_Azorult_RF_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 ?? 83 3d ?? ?? ?? ?? 1b 89 45 ?? c7 05 ?? ?? ?? ?? fc 03 cf ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}