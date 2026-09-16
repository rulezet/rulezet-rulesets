rule Trojan_Win32_Donbot_A_2{
	meta:
		description = "Trojan:Win32/Donbot.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 42 4c 3a 20 25 6c 75 0d 0a } 		$a_01_1 = {7b 42 41 53 45 36 34 45 4d 41 49 4c 7d } 		$a_01_2 = {7b 71 70 5f 73 74 61 72 74 7d } 		$a_01_3 = {4d 61 78 2d 54 68 72 65 61 64 73 3a 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}