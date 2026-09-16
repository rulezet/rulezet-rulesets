rule Trojan_BAT_Jalapeno_BAG_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 20 fb 00 00 00 5d 58 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e5 } 		$a_01_1 = {08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 08 06 08 06 09 91 9c 06 09 11 08 9c 11 04 11 07 02 11 07 91 06 06 08 91 06 09 91 58 20 00 01 00 00 5d 91 61 d2 9c 11 07 17 58 13 07 11 07 02 8e 69 32 b3 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}