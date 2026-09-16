rule Trojan_Win32_Injuke_RB_MTB_6{
	meta:
		description = "Trojan:Win32/Injuke.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 05 bc 3d 47 00 e8 c3 8c 02 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 a3 a0 3c 47 00 e8 ?? ?? fe ff 8b 15 a8 3a 47 00 a1 b8 3a 47 00 52 50 e8 ?? ?? 03 00 } 		$a_01_1 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 45 00 6d 00 70 00 74 00 79 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}