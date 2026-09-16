rule Trojan_BAT_Tedy_AT_MTB_3{
	meta:
		description = "Trojan:BAT/Tedy.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 03 02 73 ?? 00 00 0a a2 73 ?? 00 00 0a 28 ?? ?? ?? 0a 0d 08 09 6f ?? ?? ?? 0a 00 00 de 0b 08 2c 07 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}