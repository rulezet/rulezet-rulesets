rule Trojan_BAT_FormBook_MBEH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {38 00 38 00 38 00 42 00 47 00 37 00 34 00 35 00 37 00 35 00 34 00 50 00 47 00 41 00 47 00 42 00 34 00 45 00 34 00 38 00 4e 00 39 00 00 13 69 00 64 00 50 00 70 00 75 00 48 00 59 00 31 00 39 } 		$a_01_1 = {70 00 73 00 61 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}