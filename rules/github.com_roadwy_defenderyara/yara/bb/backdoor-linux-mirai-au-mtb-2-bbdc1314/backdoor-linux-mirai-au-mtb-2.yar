rule Backdoor_Linux_Mirai_AU_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.AU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 8d 45 f3 6a 01 50 56 e8 [0-05] 83 c4 10 48 [0-05] 83 ec 0c 6a 04 e8 [0-05] 83 c4 10 0f be 45 f3 c1 e3 08 09 c3 81 fb 0a 0d 0a 0d } 		$a_03_1 = {8d 9d 60 ff ff ff 51 68 80 00 00 00 53 56 e8 [0-05] ff 83 c4 10 85 c0 [0-05] 52 50 53 57 e8 [0-05] 83 c4 10 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}