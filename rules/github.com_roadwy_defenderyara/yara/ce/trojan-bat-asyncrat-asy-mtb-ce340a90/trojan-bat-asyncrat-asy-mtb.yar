rule Trojan_BAT_AsyncRat_ASY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 26 26 28 ?? ?? ?? 06 25 26 02 20 60 01 00 00 28 ?? ?? ?? 06 02 8e 69 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}