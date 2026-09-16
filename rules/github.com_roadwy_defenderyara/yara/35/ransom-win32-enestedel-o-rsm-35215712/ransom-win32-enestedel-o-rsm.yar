rule Ransom_Win32_Enestedel_O_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.O!rsm,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 50 6a 03 6a 00 6a 01 68 00 00 00 80 } 		$a_01_1 = {80 b8 02 00 40 00 47 } 		$a_01_2 = {80 b8 05 00 40 00 4d } 		$a_03_3 = {00 10 0f bf 15 90 09 05 00 0f bf 0d } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_03_3  & 1)*10) >=40
 
}