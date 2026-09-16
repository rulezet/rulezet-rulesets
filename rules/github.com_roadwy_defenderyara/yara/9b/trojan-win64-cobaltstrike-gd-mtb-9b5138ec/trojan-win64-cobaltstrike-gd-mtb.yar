rule Trojan_Win64_CobaltStrike_GD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8b c8 83 e1 3f 2b d1 8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe e8 15 04 00 eb 2d } 		$a_01_1 = {73 65 74 75 70 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}