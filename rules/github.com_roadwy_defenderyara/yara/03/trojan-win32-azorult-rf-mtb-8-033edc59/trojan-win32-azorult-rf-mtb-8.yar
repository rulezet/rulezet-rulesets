rule Trojan_Win32_Azorult_RF_MTB_8{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 2e eb ed 8b ?? ?? 8b ?? ?? 8d 1c 38 8b c7 d3 e8 8b ?? ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 89 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}