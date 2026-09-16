rule Backdoor_Linux_Gafgyt_CW_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {bf 00 2c af be 00 28 03 a0 f0 21 af bc 00 10 af c4 00 30 af c0 00 1c 8f c4 00 30 8f 99 81 78 00 } 		$a_00_1 = {a2 00 18 8f c4 00 50 00 60 28 21 24 06 00 0a 24 07 00 01 8f 82 80 20 00 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}