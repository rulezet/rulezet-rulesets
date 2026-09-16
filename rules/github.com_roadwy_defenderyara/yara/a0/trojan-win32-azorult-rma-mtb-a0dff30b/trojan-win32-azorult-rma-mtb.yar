rule Trojan_Win32_Azorult_RMA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8d ?? ?? e8 ?? ?? ?? ?? 8b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}