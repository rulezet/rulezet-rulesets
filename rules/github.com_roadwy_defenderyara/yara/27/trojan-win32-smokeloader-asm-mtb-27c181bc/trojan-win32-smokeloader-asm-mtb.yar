rule Trojan_Win32_SmokeLoader_ASM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 33 c0 8d 54 24 1c 89 44 24 1c 89 44 24 20 89 44 24 24 89 44 24 28 89 44 24 2c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}