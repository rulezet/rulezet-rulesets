rule Rogue_Win32_PrivacyCenter_2{
	meta:
		description = "Rogue:Win32/PrivacyCenter,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ba 07 00 00 00 e8 ?? ?? ?? ?? c3 e9 ?? ?? ?? ?? eb eb 5b e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0d 00 00 00 75 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 00 00 00 53 61 66 65 74 79 20 43 65 6e 74 65 72 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}