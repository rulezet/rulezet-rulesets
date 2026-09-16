rule Backdoor_Linux_Mirai_CA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {f0 40 2d e9 48 70 9f e5 00 20 97 e5 03 00 52 e3 40 60 9f e5 01 50 82 e2 21 4c a0 e1 21 c4 a0 e1 21 e8 a0 e1 ff 00 00 e2 f0 80 bd 08 05 30 a0 e3 93 02 02 e0 06 30 82 e0 06 00 c2 e7 00 50 87 e5 04 40 c3 e5 02 c0 c3 e5 03 e0 c3 e5 01 10 c3 e5 f0 80 bd e8 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}