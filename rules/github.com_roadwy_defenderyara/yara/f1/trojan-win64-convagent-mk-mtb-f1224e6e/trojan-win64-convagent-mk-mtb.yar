rule Trojan_Win64_Convagent_MK_MTB{
	meta:
		description = "Trojan:Win64/Convagent.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 63 c1 48 8d 05 0f e8 ff ff 48 89 44 24 30 c6 44 24 20 00 48 8d 15 1e 41 03 00 48 8d 4c 24 30 } 		$a_01_1 = {48 89 4c 24 30 48 8d 0d 12 49 03 00 48 89 4c 24 20 48 8d 15 26 49 03 00 4c 8d 4c 24 30 41 b8 04 00 00 00 48 89 c1 } 	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}