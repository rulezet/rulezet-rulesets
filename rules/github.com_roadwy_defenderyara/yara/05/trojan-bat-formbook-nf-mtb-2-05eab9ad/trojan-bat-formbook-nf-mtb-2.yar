rule Trojan_BAT_FormBook_NF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4a 6f 67 6f 44 61 73 50 61 6c 61 76 72 61 73 } 		$a_01_1 = {24 38 34 35 66 61 37 65 62 2d 32 61 36 30 2d 34 38 63 35 2d 39 35 32 34 2d 32 32 64 31 62 39 64 63 65 39 34 36 } 		$a_01_2 = {46 72 6d 46 6f 72 63 61 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}