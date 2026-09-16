rule Trojan_BAT_Krypt_PGK_MTB_4{
	meta:
		description = "Trojan:BAT/Krypt.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_80_0 = {56 46 68 77 54 6d 56 72 4e 55 56 55 56 45 4a 4f 5a 57 78 47 4e 6c 52 59 63 45 35 4e 56 54 45 32 56 56 68 77 54 6c 5a 46 4d 54 5a 55 57 48 42 79 } 	condition:
		((#a_80_0  & 1)*5) >=5
 
}