rule Trojan_Win32_Azorult_RT_MTB_18{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 45 ?? 03 ?? ?? 33 d0 89 ?? ?? 8b ?? ?? 29 ?? ?? 25 bb 52 c0 5d 8b ?? ?? 8b c2 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}