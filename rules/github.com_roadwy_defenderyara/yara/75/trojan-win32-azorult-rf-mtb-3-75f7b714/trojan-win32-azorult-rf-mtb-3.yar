rule Trojan_Win32_Azorult_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 c7 05 ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 81 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}