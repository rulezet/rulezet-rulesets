rule Trojan_Win32_MarsStealer_MA_MTB{
	meta:
		description = "Trojan:Win32/MarsStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 8b 4c 24 10 c1 e8 05 03 44 24 28 33 cb c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 18 89 4c 24 10 8b 44 24 18 31 44 24 10 2b 74 24 10 81 c7 ?? ?? ?? ?? 4d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}