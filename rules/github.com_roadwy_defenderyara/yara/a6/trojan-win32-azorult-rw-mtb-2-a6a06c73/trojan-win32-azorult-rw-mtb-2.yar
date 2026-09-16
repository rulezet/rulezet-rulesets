rule Trojan_Win32_Azorult_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 33 ?? 31 ?? ?? 8b ?? ?? 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}