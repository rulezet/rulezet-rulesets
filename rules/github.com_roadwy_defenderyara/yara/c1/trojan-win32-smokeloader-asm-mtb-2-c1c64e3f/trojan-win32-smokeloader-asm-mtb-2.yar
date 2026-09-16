rule Trojan_Win32_SmokeLoader_ASM_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 05 61 b8 42 00 69 c6 05 62 b8 42 00 72 c6 05 67 b8 42 00 50 c6 05 6d b8 42 00 74 c6 05 6e b8 42 00 00 c6 05 63 b8 42 00 74 c6 05 6c b8 42 00 63 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}