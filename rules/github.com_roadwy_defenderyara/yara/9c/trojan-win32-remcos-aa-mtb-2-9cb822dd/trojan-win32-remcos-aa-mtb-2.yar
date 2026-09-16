rule Trojan_Win32_Remcos_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 a8 3b 45 a4 ?? ?? ?? 8b 45 a4 31 45 a8 8b 45 a8 31 45 a4 8b 45 a4 31 45 a8 6a 04 68 00 10 00 00 8b 45 a8 03 45 b0 50 } 		$a_01_1 = {81 c2 a1 03 00 00 87 d1 29 d3 33 c0 5a 59 59 64 89 10 68 6e 80 46 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}