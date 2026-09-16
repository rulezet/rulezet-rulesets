rule Backdoor_Linux_Dakkatoni_B_MTB{
	meta:
		description = "Backdoor:Linux/Dakkatoni.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_00_0 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 65 20 13 06 68 02 00 11 5c 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 27 } 	condition:
		((#a_00_0  & 1)*3) >=3
 
}