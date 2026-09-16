rule Trojan_Win64_Icedid_E_MTB{
	meta:
		description = "Trojan:Win64/Icedid.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 48 8d 49 01 83 e0 03 ff c2 0f b6 44 30 2c 30 41 ff 3b d7 72 e9 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}