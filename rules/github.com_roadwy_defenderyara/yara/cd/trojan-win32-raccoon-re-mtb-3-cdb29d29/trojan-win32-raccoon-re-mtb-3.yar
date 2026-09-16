rule Trojan_Win32_Raccoon_RE_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {af 9e 1b 2c c7 44 24 ?? 30 2e 52 49 c7 84 24 ?? 00 00 00 7a cd 12 6e c7 84 24 ?? ?? ?? ?? c5 53 ef 46 b8 64 cb bc 3b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}