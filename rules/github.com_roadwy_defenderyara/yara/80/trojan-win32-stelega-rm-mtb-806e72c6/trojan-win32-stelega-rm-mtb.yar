rule Trojan_Win32_Stelega_RM_MTB{
	meta:
		description = "Trojan:Win32/Stelega.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {81 c7 38 33 fa 44 e8 ?? ?? ?? ?? 89 d7 81 c7 15 ac e1 5d 89 ff 31 06 09 d7 81 c6 01 00 00 00 01 fa 39 ce 75 } 		$a_03_1 = {81 ef 76 eb 7c bf 48 e8 ?? ?? ?? ?? 81 c0 dd 1f dc 4c 31 16 68 ?? ?? ?? ?? 58 48 46 01 ff 81 ef } 		$a_03_2 = {81 c0 c1 78 8b ee e8 ?? ?? ?? ?? 09 c1 31 16 21 c0 46 51 58 29 c1 } 		$a_03_3 = {83 c4 04 e8 ?? ?? ?? ?? 01 c9 09 c9 21 c9 31 16 bb 3f df eb 74 01 cb 4b 46 81 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}