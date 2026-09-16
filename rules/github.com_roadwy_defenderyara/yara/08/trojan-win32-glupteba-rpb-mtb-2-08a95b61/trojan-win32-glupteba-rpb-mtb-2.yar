rule Trojan_Win32_Glupteba_RPB_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 18 81 c2 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 81 c0 04 00 00 00 09 fa 39 f0 75 e1 } 		$a_03_1 = {31 30 21 d1 81 c1 ?? ?? ?? ?? 81 c0 04 00 00 00 01 d1 39 f8 75 e5 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}