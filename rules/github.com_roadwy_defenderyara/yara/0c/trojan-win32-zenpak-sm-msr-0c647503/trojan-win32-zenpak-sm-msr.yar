rule Trojan_Win32_Zenpak_SM_MSR{
	meta:
		description = "Trojan:Win32/Zenpak.SM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 94 07 f8 94 08 00 8b 1d ?? ?? ?? 00 88 14 03 81 f9 03 02 00 00 90 13 40 3b c1 } 		$a_02_1 = {30 04 1e 83 ff 19 90 13 46 3b f7 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}