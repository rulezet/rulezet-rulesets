rule Trojan_Win64_Zusy_MR_MTB_3{
	meta:
		description = "Trojan:Win64/Zusy.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 15 ac 1e 0d 00 8b c2 83 e0 3f 48 8b da 48 33 1d 85 49 0d 00 8b c8 48 d3 cb b9 40 00 00 00 2b c8 48 d3 cf 48 33 fa 48 89 3d 6c 49 0d 00 33 c9 } 		$a_01_1 = {4c 8b 15 cd 13 0d 00 41 8b ca 49 8b f2 48 33 32 83 e1 3f 4d 8b ca 48 d3 ce 4c 33 4a 08 49 8b da 48 33 5a 10 49 d3 c9 48 d3 cb 4c 3b cb } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*10) >=15
 
}