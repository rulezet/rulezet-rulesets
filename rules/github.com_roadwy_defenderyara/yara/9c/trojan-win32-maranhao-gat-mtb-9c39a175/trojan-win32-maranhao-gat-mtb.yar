rule Trojan_Win32_Maranhao_GAT_MTB{
	meta:
		description = "Trojan:Win32/Maranhao.GAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 04 ?? ?? ?? 04 00 92 3a 00 ?? ?? ?? ?? ?? ?? ?? 04 00 e4 11 } 	condition:
		((#a_03_0  & 1)*8) >=8
 
}