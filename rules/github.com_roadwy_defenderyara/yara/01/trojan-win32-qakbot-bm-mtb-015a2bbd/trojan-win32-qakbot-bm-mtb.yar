rule Trojan_Win32_QakBot_BM_MTB{
	meta:
		description = "Trojan:Win32/QakBot.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 d8 33 18 89 5d a0 } 		$a_01_1 = {8b 45 a8 03 45 ac 48 89 45 a4 8b 45 a8 8b 55 d8 01 02 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}