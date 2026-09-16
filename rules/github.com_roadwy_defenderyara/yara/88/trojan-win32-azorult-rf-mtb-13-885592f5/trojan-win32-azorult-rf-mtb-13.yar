rule Trojan_Win32_Azorult_RF_MTB_13{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b ?? ?? 33 ?? ?? 89 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}