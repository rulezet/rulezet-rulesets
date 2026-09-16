rule Trojan_Win32_StealC_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 3e 2c ?? 34 ?? 88 04 3e 46 57 e8 ?? ?? ?? ?? 59 3b f0 72 ea } 		$a_01_1 = {53 8d 44 24 14 89 5c 24 14 50 53 68 3f 00 0f 00 53 53 53 8d 84 24 3c 04 00 00 50 68 01 00 00 80 ff } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}