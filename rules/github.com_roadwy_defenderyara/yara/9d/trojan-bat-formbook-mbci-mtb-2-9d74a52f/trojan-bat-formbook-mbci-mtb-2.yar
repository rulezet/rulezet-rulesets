rule Trojan_BAT_FormBook_MBCI_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.MBCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 31 63 61 64 63 38 66 65 2d 37 63 66 38 2d 34 34 32 32 2d 62 66 64 39 2d 32 39 61 64 35 34 64 65 64 37 38 61 } 		$a_01_1 = {55 6e 69 76 65 72 73 65 53 69 6d 75 6c 61 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}