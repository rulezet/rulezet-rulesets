rule Trojan_Win32_Glupteba_RPJ_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {39 db 74 01 ea 31 17 01 c0 81 c7 04 00 00 00 01 c3 39 cf 75 eb } 		$a_01_1 = {39 d2 74 01 ea 31 32 81 c2 04 00 00 00 09 c3 39 fa 75 ed } 		$a_01_2 = {39 c9 74 01 ea 31 0e 81 ea 04 1f 06 30 81 c6 04 00 00 00 29 fa 89 df 39 c6 75 e5 } 		$a_01_3 = {39 c9 74 01 ea 31 18 81 c0 04 00 00 00 49 39 f0 75 ee } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}