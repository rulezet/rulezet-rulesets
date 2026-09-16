rule Trojan_BAT_FormBook_EVO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EVO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 06 07 91 61 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d da } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}