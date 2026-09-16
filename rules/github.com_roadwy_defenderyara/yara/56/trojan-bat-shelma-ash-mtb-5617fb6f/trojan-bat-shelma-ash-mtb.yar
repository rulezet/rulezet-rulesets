rule Trojan_BAT_Shelma_ASH_MTB{
	meta:
		description = "Trojan:BAT/Shelma.ASH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 11 2b 37 11 0e 11 11 91 18 59 2d 15 11 0e 11 11 11 0e 11 11 91 1b 59 20 ff 00 00 00 5f d2 9c 2b 13 11 0e 11 11 11 0e 11 11 91 1b 59 20 ff 00 00 00 5f d2 9c 11 11 17 58 13 11 11 11 11 0e 8e 69 32 c1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}