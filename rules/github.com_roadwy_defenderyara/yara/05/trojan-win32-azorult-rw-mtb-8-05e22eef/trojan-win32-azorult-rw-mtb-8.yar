rule Trojan_Win32_Azorult_RW_MTB_8{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 ?? c7 05 ?? ?? ?? ?? b4 02 d7 cb 89 45 ?? 33 45 ?? c7 05 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}