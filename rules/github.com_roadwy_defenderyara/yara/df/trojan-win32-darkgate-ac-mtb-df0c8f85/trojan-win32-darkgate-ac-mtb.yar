rule Trojan_Win32_DarkGate_AC_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 f7 74 24 ?? 2b d1 8a 44 14 ?? 32 87 ?? ?? ?? ?? 88 04 3e 47 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}