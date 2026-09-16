rule Trojan_Win32_Remcos_ARE_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 20 b5 45 00 a1 40 58 4b 00 50 e8 ?? ?? ?? ?? a3 84 65 5b 00 68 30 b5 45 00 a1 40 58 4b 00 50 e8 ?? ?? ?? ?? a3 88 65 5b 00 68 44 b5 45 00 a1 40 58 4b 00 50 e8 } 		$a_03_1 = {68 40 e5 42 00 8b 03 50 e8 ?? ?? ?? ?? a3 48 64 5b 00 68 4c e5 42 00 8b 03 50 e8 ?? ?? ?? ?? a3 4c 64 5b 00 68 5c e5 42 00 8b 03 50 e8 ?? ?? ?? ?? a3 50 64 5b 00 68 78 e5 42 00 8b 03 50 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}