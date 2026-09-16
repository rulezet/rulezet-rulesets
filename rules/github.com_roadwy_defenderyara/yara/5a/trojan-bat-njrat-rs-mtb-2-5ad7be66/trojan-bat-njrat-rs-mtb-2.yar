rule Trojan_BAT_NJRat_RS_MTB_2{
	meta:
		description = "Trojan:BAT/NJRat.RS!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 6f 44 00 00 0a 17 da 2b 2c 16 0d 2b 2b 7e 0d 00 00 04 07 09 16 6f 45 00 00 0a 13 04 12 04 28 46 00 00 0a 2b 03 } 		$a_01_1 = {09 17 d6 0d 2b 03 0c 2b d1 09 08 31 02 2b 05 2b cd 0b 2b bc } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}