rule Trojan_Win32_Azorult_RW_MTB_11{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 34 07 e8 ?? ?? ?? ?? 30 06 83 7d ?? 19 75 ?? 53 53 53 53 ff 15 ?? ?? ?? ?? 47 3b 7d ?? 7c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}