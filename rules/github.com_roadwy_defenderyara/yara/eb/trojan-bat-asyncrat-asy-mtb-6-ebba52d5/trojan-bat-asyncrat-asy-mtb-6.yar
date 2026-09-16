rule Trojan_BAT_AsyncRat_ASY_MTB_6{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 2d 06 08 6f ?? ?? ?? 0a 03 08 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 0d 07 09 28 ?? ?? ?? 0a 8c 3e 00 00 01 28 ?? ?? ?? 0a 0b 08 17 58 0c 08 06 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}