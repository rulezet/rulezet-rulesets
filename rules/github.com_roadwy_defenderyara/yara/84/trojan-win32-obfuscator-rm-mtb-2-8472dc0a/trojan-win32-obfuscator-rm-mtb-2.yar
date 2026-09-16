rule Trojan_Win32_Obfuscator_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b df 3b fe 73 ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 8b 54 24 ?? 8a c3 2a 44 24 ?? 83 c4 04 32 03 51 32 44 24 ?? 52 88 03 ff 15 ?? ?? ?? ?? 03 5c 24 ?? 3b de 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}