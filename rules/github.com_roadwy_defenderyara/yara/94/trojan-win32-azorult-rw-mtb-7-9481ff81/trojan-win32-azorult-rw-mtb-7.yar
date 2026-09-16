rule Trojan_Win32_Azorult_RW_MTB_7{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 c6 47 86 c8 61 ff 8d ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8b 45 ?? 5f 89 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}