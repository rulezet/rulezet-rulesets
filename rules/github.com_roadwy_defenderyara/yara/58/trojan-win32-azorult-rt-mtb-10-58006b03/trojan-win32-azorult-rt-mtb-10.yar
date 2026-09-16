rule Trojan_Win32_Azorult_RT_MTB_10{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 eb c7 05 ?? ?? ?? ?? 2e ce 50 91 89 45 ?? 03 9d ?? ?? ?? ?? 33 d8 81 3d ?? ?? ?? ?? b7 01 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}