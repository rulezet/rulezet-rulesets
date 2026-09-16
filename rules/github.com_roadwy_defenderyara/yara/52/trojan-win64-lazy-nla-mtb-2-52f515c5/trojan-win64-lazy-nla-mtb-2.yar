rule Trojan_Win64_Lazy_NLA_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8d 50 02 33 c9 48 8b 03 ff 15 ?? ?? ?? ?? e8 13 07 00 00 48 8b d8 48 83 38 00 74 14 } 		$a_03_1 = {48 8d 4c 24 20 e8 1e e6 ff ff 48 8d 15 5f 9a 04 00 48 8d 4c 24 ?? e8 dd 1e 00 00 cc 33 c0 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}