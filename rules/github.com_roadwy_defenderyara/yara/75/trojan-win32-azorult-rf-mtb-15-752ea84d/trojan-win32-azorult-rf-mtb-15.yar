rule Trojan_Win32_Azorult_RF_MTB_15{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 03 4d ?? 89 4d ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b 55 ?? 33 55 ?? 89 55 ?? 81 3d ?? ?? ?? ?? 8d 00 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}