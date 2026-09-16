rule Trojan_Win32_QakbotPacker_MTB{
	meta:
		description = "Trojan:Win32/QakbotPacker!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 1c 30 [0-30] 83 e2 00 [0-30] d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d ?? 75 } 		$a_03_1 = {0f b6 1c 30 [0-30] d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d ?? 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}