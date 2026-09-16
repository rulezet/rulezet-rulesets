rule Trojan_Win32_QakBot_CM_MTB{
	meta:
		description = "Trojan:Win32/QakBot.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_00_0 = {ff 75 14 ff 75 10 3a c9 74 e1 33 ed c1 e8 f6 f7 fd f7 df c1 ef 00 0b d9 81 ea 89 25 00 00 0b d1 96 c8 49 00 00 f7 d5 } 		$a_01_1 = {41 41 6c 42 6c 50 6c 34 6d } 		$a_01_2 = {43 6c 61 71 47 7a 55 6b 4d 4b } 		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}