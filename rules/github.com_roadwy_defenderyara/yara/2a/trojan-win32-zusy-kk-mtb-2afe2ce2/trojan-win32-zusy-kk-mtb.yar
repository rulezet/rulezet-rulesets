rule Trojan_Win32_Zusy_KK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 6a 01 6a 02 83 ec 0c 8b 44 24 14 83 c0 3c 8b 00 03 44 24 14 83 c0 78 85 c0 0f 84 aa 00 00 00 } 		$a_01_1 = {b6 12 00 d6 b6 12 00 e6 b6 12 00 fc b6 12 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}