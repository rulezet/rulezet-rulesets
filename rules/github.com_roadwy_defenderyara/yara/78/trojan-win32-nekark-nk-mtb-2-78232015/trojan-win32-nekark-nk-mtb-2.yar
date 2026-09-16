rule Trojan_Win32_Nekark_NK_MTB_2{
	meta:
		description = "Trojan:Win32/Nekark.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 7b 3b c2 77 13 e8 63 25 ff ff 8b fc 85 ff 74 6e c7 07 ?? ?? 00 00 eb 13 50 } 		$a_03_1 = {e8 8f 01 00 00 8b f8 59 85 ff 74 59 c7 07 ?? ?? 00 00 83 c7 08 85 ff 74 4c 33 c0 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}