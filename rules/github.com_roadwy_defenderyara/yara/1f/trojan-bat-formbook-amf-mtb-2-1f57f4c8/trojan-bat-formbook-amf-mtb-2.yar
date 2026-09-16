rule Trojan_BAT_FormBook_AMF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 46 16 0d 2b 3a 16 13 04 2b 2c 11 07 07 09 58 08 11 04 58 6f ?? ?? ?? 0a 13 0b 12 0b 28 ?? ?? ?? 0a 13 09 11 06 11 05 11 09 9c 11 05 17 58 13 05 11 04 17 58 13 04 11 04 17 32 cf } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}