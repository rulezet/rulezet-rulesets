rule Trojan_Win32_Dridex_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {55 89 e5 56 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 8a 24 0a 34 ff 00 c4 88 24 0e 5e 5d c3 } 		$a_02_1 = {8b 4d e8 8b 55 ec 8a 5d e7 32 5d de 29 d0 8b 55 b4 88 1c 0a 8b 4d d8 03 45 e8 89 4d c8 89 45 c4 8b 4d c0 89 4d d0 8b 4d bc 39 c8 0f 84 ?? ?? 00 00 e9 ?? ?? 00 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}