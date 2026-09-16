rule Trojan_BAT_Krypt_PGK_MTB_3{
	meta:
		description = "Trojan:BAT/Krypt.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_80_0 = {54 6b 56 52 4d 56 46 55 61 33 64 4e 52 45 46 33 54 58 70 42 64 30 31 45 51 58 64 4e 52 45 45 77 54 55 52 42 64 30 31 45 51 58 64 53 61 31 70 48 } 	condition:
		((#a_80_0  & 1)*5) >=5
 
}