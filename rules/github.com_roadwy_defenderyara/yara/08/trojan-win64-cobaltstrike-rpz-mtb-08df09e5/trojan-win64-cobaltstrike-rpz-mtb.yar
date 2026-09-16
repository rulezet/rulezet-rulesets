rule Trojan_Win64_Cobaltstrike_RPZ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e8 41 03 d0 c1 fa 09 8b ca c1 e9 1f 03 d1 69 ca ac 03 00 00 44 2b c1 41 fe c0 44 32 44 2b ff 45 32 c7 44 88 43 ff 48 83 ef 01 75 c0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}