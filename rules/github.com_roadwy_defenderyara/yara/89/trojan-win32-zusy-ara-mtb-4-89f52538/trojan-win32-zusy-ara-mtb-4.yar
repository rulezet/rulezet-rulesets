rule Trojan_Win32_Zusy_ARA_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 56 57 6a 40 bf 50 c6 04 00 68 00 30 00 00 33 db 57 53 ff 15 10 10 40 00 } 		$a_01_1 = {53 53 56 56 53 53 ff 15 14 10 40 00 } 		$a_01_2 = {6a ff 50 ff 15 18 10 40 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}