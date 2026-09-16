rule Trojan_Win32_Emotet_BF_2{
	meta:
		description = "Trojan:Win32/Emotet.BF,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 72 66 5a 50 70 32 43 2e 70 64 62 } 		$a_01_1 = {4c 51 59 75 74 6f 58 52 4a 70 51 42 49 2d 7a 79 56 65 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}