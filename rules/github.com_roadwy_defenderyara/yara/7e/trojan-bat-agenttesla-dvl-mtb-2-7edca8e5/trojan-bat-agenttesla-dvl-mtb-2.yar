rule Trojan_BAT_AgentTesla_DVL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {c9 f9 4f 0e c0 ff f7 1f f0 65 ef e0 4b 1d f0 77 1d 30 ed dd f0 41 07 fc b3 e3 9a 8d 6c 2d ee df ef 80 cf 39 e0 57 1c 40 f7 e8 6e c1 67 de 1d f9 } 		$a_01_1 = {f8 3f 82 72 44 4d d5 1f 59 62 25 1f f8 d2 3a 90 2d e6 50 73 b9 ba 62 1f 9b fd e6 73 75 19 9e 0c 73 14 9b ec fb f0 85 9a 80 9f 2c 73 9f 98 b0 d3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}