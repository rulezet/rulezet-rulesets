rule Trojan_BAT_Kryptik_WR_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.WR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {6e 17 6a d6 20 [0-04] 6a 5f b8 0c 09 11 05 08 84 95 d7 6e 20 [0-04] 6a 5f b8 0d 11 05 08 84 95 13 04 11 05 08 84 11 05 09 84 95 9e 11 05 09 84 11 04 } 		$a_03_1 = {9e 11 06 11 07 02 11 07 91 11 05 11 05 08 84 95 11 05 09 84 95 d7 6e 20 [0-04] 6a 5f b7 95 61 86 9c 11 07 17 d6 13 07 11 07 11 0a 31 9b } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}