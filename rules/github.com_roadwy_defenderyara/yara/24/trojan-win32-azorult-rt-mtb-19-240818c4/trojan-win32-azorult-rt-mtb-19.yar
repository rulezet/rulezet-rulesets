rule Trojan_Win32_Azorult_RT_MTB_19{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c7 05 ?? ?? ?? ?? 2e ce 50 91 e8 ?? ?? ?? ?? 8b ?? ?? d3 ee 89 ?? ?? 03 ?? ?? 33 f0 2b fe 25 bb 52 c0 5d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}