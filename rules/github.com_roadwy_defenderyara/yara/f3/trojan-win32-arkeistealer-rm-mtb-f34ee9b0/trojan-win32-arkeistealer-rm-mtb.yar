rule Trojan_Win32_ArkeiStealer_RM_MTB{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 e9 4c a6 b5 f2 e8 ?? ?? ?? ?? 43 bb 44 c5 9a c3 31 32 89 c9 42 01 cb bb 26 05 bb 1f 39 fa 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}