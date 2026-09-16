rule Trojan_Win32_Azorult_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 4d ec 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 [0-05] fc 03 cf ff 81 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}