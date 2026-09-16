rule Trojan_Win32_TrickBot_I{
	meta:
		description = "Trojan:Win32/TrickBot.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 83 c0 0c c6 80 ?? ?? ?? ?? 00 8b 45 0c [0-03] 89 45 ?? eb ?? 8b 45 ?? 83 c0 0c c6 80 ?? ?? ?? ?? 01 [0-04] 83 7d ?? ?? [0-07] c7 45 ?? 00 00 00 00 c7 45 ?? 4c 00 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}