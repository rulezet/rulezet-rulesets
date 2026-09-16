rule Trojan_Win32_Ekstak_RK_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 05 7c 4b 08 01 68 ?? ?? ?? ?? e8 ?? 00 00 00 59 a3 ?? 4b 08 01 e8 ?? 00 00 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 31 05 ?? 4b 08 01 e8 ?? ?? 00 00 33 c0 50 50 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}