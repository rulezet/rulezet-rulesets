rule Trojan_Win32_Azorult_RW_MTB_9{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fc 03 cf ff 8b 90 09 32 00 [0-32] d3 ?? 89 ?? ?? 8b ?? ?? 01 ?? ?? c7 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}