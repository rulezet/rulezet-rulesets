rule Trojan_Win32_Azorult_RT_MTB_20{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c7 05 ?? ?? ?? ?? 2e ce 50 91 e8 ?? ?? ?? ?? 8b 4d ?? 8b fe d3 ef 03 7d ?? 33 f8 81 fa 8f 01 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}