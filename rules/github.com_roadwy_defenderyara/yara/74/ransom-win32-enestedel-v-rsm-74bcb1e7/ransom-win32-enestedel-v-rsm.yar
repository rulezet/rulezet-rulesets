rule Ransom_Win32_Enestedel_V_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.V!rsm,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd2 00 ffffffd2 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 00 00 00 80 90 0a 34 00 6a 50 [0-18] 6a 03 [0-20] 6a 01 } 		$a_03_1 = {6a 40 68 00 30 00 00 [0-10] 68 96 02 00 } 		$a_03_2 = {68 96 02 00 00 90 0a 10 00 68 00 30 00 00 90 0a 18 00 6a 40 } 		$a_01_3 = {05 00 40 00 46 } 		$a_01_4 = {06 00 40 00 46 } 	condition:
		((#a_03_0  & 1)*100+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=210
 
}