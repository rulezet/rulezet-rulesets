rule Trojan_Win64_Emotet_EH_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 14 02 43 32 14 0b 41 88 11 49 ff c1 48 83 ef 01 75 c6 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}