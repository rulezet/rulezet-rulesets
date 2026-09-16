rule Trojan_Win32_Farfli_MC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 74 24 18 8b 57 54 8b f8 53 8b 4e 3c 03 ca 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8b 4c 24 1c 8b 74 24 14 56 51 8b 51 3c 03 c2 89 03 89 68 34 } 		$a_03_1 = {8a 14 08 8b 2f 8b da 81 e3 ?? ?? ?? ?? 03 dd 03 f3 81 e6 ?? ?? ?? ?? 79 08 4e 81 ce ?? ?? ?? ?? 46 8a 1c 0e 83 c7 04 88 1c 08 40 3d ?? ?? ?? ?? 88 14 0e 7c } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}