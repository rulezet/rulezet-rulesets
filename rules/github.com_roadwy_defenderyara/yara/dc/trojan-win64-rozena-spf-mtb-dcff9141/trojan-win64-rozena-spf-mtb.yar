rule Trojan_Win64_Rozena_SPF_MTB{
	meta:
		description = "Trojan:Win64/Rozena.SPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 00 00 00 00 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01 83 45 f8 01 eb 9d } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}