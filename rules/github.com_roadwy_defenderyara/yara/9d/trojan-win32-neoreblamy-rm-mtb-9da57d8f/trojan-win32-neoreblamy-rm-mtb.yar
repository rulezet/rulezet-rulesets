rule Trojan_Win32_Neoreblamy_RM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 75 08 8d 45 d4 89 5d fc 56 6a 00 68 8c 2b 00 00 68 a7 00 00 00 50 ba 12 0c 00 00 b9 8d 6b 00 00 e8 } 		$a_03_1 = {49 49 23 c8 74 ?? 33 c0 40 8b ?? ?? ?? ?? ?? d3 e0 8b ?? ?? ?? ?? ?? 2b c8 89 90 09 0e 00 d3 e0 8b ?? ?? ?? ?? ?? 2b } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}