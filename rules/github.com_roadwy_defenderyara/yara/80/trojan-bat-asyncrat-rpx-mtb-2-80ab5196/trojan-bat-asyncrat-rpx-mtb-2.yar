rule Trojan_BAT_AsyncRat_RPX_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 07 00 59 3b 40 01 00 00 fe 0c 02 00 1f fe fe 0e 08 00 fe 0c 08 00 65 3b e7 00 00 00 fe 0c 02 00 1f fc fe 0e 09 00 16 fe 0e 0a 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}