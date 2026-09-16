rule Trojan_Win64_IcedID_BM_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {e6 19 48 f7 f2 48 c1 ef 3d 48 81 e3 b6 1b 00 00 e4 b0 49 81 e8 c7 0a 00 00 4c 0b c0 48 81 dc 8b 21 00 00 48 81 ea ca 17 00 00 48 ff cd e4 de e6 ff 49 81 cf 98 22 00 00 48 f7 f8 41 59 } 		$a_01_1 = {49 46 50 47 70 78 58 61 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}