rule Trojan_Win32_Azorult_RW_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 2e eb ed 8b ?? ?? 8b c6 d3 e8 8b ?? ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}