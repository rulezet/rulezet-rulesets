rule Trojan_Win32_Azorult_RW_MTB_6{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ef 89 45 ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 83 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}