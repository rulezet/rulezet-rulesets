rule Trojan_Win32_Napolar_A{
	meta:
		description = "Trojan:Win32/Napolar.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 3d 25 64 2e 25 64 26 75 3d 25 73 26 63 3d 25 73 26 73 3d 25 73 26 77 3d 25 64 2e } 		$a_03_1 = {8b 10 81 fa 50 45 00 00 0f 85 ?? ?? ?? ?? 89 85 ?? ?? ff ff 8b 95 ?? ?? ff ff 8b 42 78 03 85 ?? ?? ff ff 89 85 ?? ?? ff ff 8b 50 18 4a } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}