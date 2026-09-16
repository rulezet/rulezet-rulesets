rule Trojan_Win32_Azorult_RW_MTB_10{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea c7 05 ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 81 ?? ?? ?? ?? ?? ff 03 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}