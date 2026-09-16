rule Trojan_Win32_Azorult_RT_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 ?? 8b ?? ?? 01 ?? ?? c7 [0-05] 64 61 15 fe 8b ?? ?? 81 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}