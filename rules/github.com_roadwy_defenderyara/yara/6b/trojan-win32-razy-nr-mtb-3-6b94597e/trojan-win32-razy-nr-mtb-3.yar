rule Trojan_Win32_Razy_NR_MTB_3{
	meta:
		description = "Trojan:Win32/Razy.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 3f 81 eb ?? ?? ?? ?? 01 c9 81 e7 ?? ?? ?? ?? 89 d9 29 cb 81 c2 ?? ?? ?? ?? 89 cb 89 d9 81 fa ?? ?? ?? ?? 75 05 ba 00 00 00 00 01 cb } 		$a_03_1 = {31 3e f7 d3 89 d9 21 c9 81 c6 ?? ?? ?? ?? 81 c1 01 00 00 00 21 c9 49 39 c6 0f 8c 96 ff ff ff } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}