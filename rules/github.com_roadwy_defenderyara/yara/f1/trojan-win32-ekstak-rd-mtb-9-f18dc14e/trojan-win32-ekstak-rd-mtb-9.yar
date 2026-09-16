rule Trojan_Win32_Ekstak_RD_MTB_9{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f1 a3 ?? ?? ?? 00 e8 ?? 00 00 00 6a 00 6a 00 e8 90 09 19 00 6a 32 e8 ?? ?? ?? 00 01 05 ?? ?? ?? 00 e8 ?? ?? ?? 00 8b c8 b8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}