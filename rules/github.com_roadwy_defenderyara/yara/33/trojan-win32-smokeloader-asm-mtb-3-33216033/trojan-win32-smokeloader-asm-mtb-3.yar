rule Trojan_Win32_SmokeLoader_ASM_MTB_3{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 04 24 e8 a5 42 00 57 a3 20 e9 42 00 ff d6 50 e8 ?? ?? ?? ?? c7 04 24 d4 a5 42 00 57 a3 24 e9 42 00 ff d6 50 e8 ?? ?? ?? ?? c7 04 24 b8 a5 42 00 57 a3 28 e9 42 00 ff d6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}