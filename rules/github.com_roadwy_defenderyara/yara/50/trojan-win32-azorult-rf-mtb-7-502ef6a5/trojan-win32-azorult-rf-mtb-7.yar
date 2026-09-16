rule Trojan_Win32_Azorult_RF_MTB_7{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 e0 89 45 ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 33 ?? ?? 89 ?? ?? c7 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}