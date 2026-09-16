rule Trojan_Win32_Azorult_RT_MTB_11{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f0 89 45 ?? 89 75 ?? 8b 45 ?? 29 45 ?? 25 bb 52 c0 5d 8b 55 ?? 8b c2 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}