rule Trojan_Win32_Ekstak_RC_MTB_13{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 46 07 00 00 59 a3 ?? 0b 08 01 e8 ?? 07 00 00 8b c8 33 d2 b8 ?? ?? ?? ?? f7 f1 31 05 7c 0b 08 01 e8 ?? 0d 00 00 33 c0 50 50 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}