rule Trojan_Win32_Ekstak_SM_MSR{
	meta:
		description = "Trojan:Win32/Ekstak.SM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b7 03 2a fb a1 ?? ?? ?? 00 03 f8 66 33 c0 8a 65 f8 80 c7 14 0a c3 30 27 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}