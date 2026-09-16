rule Trojan_BAT_Stelpak_EADV_MTB{
	meta:
		description = "Trojan:BAT/Stelpak.EADV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 08 28 1f 00 00 0a 9c 07 08 04 08 05 5d 91 9c 08 17 58 0c 08 20 00 01 00 00 3f e0 ff ff ff } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}