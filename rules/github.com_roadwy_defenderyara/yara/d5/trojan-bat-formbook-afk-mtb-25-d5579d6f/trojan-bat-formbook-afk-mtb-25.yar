rule Trojan_BAT_FormBook_AFK_MTB_25{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 09 6f ?? ?? ?? 0a 13 0b 16 13 0c 11 05 11 08 9a 72 55 04 00 70 28 ?? ?? ?? 0a 13 0d 11 0d 2c 0d 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 2b 42 11 05 11 08 9a 72 59 04 00 70 28 ?? ?? ?? 0a 13 0e 11 0e 2c 0d 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 2b 20 11 05 11 08 9a 72 5d 04 00 70 28 ?? ?? ?? 0a 13 0f 11 0f 2c 0b 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 07 11 0c } 		$a_01_1 = {43 00 53 00 44 00 4c 00 5f 00 51 00 4c 00 4e 00 53 00 5f 00 51 00 4c 00 4c 00 55 00 4f 00 4e 00 47 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}