rule Trojan_Win32_Dridex_GD_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_02_0 = {88 e8 f6 e2 88 44 24 ?? 8a 44 24 ?? 8b 74 24 ?? 81 e6 74 db 20 7e 89 74 24 ?? c7 44 24 ?? 00 00 00 00 8b 75 ?? 8b 7d ?? 88 04 37 8d 65 } 		$a_80_1 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } 		$a_80_2 = {42 65 74 61 74 72 65 65 6b 69 6e 67 33 73 65 65 63 65 73 65 73 6f 65 76 69 6e 67 2e 31 32 33 66 6f 72 58 65 6d 65 74 69 66 } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=14
 
}