rule Trojan_Win32_Azorult_RT_MTB_25{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4d ?? 03 ce 51 03 55 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 89 55 ?? e8 ?? ?? ?? ?? 89 45 ?? 81 fb e6 09 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}