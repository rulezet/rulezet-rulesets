rule Trojan_Win64_Zusy_KK_MTB{
	meta:
		description = "Trojan:Win64/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 30 01 45 30 51 01 45 30 41 02 41 30 51 03 49 83 c1 04 83 e9 } 		$a_01_1 = {8a 44 0c 50 48 ff c1 41 30 01 49 ff c1 48 3b ca } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}