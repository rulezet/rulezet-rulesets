rule Trojan_Win64_Emotet_AM_MTB{
	meta:
		description = "Trojan:Win64/Emotet.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 32 4c 32 fd 83 c5 03 88 4e fd 41 8d 48 ff f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 48 98 48 8d 0c 40 } 	condition:
		((#a_01_0  & 1)*8) >=8
 
}