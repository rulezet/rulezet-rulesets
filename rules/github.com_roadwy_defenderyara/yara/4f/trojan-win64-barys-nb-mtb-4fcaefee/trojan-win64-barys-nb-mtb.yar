rule Trojan_Win64_Barys_NB_MTB{
	meta:
		description = "Trojan:Win64/Barys.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 07 09 c0 74 4a 8b 5f 04 48 8d 8c 30 ?? ?? ?? ?? 48 01 f3 48 83 c7 08 ff 15 60 0b 00 00 48 95 } 		$a_01_1 = {48 89 f9 48 89 fa ff c8 f2 ae 48 89 e9 ff 15 52 0b 00 00 48 09 c0 74 09 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}