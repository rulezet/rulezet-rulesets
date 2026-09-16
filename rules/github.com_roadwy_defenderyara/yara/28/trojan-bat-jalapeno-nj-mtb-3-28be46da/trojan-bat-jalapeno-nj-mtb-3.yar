rule Trojan_BAT_Jalapeno_NJ_MTB_3{
	meta:
		description = "Trojan:BAT/Jalapeno.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 8d 5d 00 00 01 0b 16 72 01 00 00 70 72 01 00 00 70 07 06 02 7b 5b 00 00 04 28 0e 01 00 06 0c 08 06 18 59 fe 04 0d 09 13 04 11 04 2c 03 00 2b 07 06 18 5a 0a } 		$a_01_1 = {28 3f 00 00 0a 07 16 08 08 16 30 03 16 2b 01 17 59 6f 00 01 00 0a } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}