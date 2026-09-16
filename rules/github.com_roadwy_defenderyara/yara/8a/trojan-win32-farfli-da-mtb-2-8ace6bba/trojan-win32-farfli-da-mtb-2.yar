rule Trojan_Win32_Farfli_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.DA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 01 00 00 00 66 3b cb 75 02 33 db 80 04 3e 86 6a 00 ff d5 6a 00 ff d5 6a 00 ff d5 0f b7 d3 8a 44 54 14 30 04 3e 46 43 3b 74 24 10 7c d2 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}