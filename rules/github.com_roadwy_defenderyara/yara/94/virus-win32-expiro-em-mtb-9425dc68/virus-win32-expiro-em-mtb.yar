rule Virus_Win32_Expiro_EM_MTB{
	meta:
		description = "Virus:Win32/Expiro.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 3d 84 d0 44 00 01 75 05 e8 68 8c 0d 00 } 		$a_01_1 = {8b f0 85 f6 75 0d 6a 12 e8 41 7e 0c 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}