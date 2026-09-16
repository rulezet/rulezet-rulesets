rule Trojan_Win64_Amadey_PGAP_MTB{
	meta:
		description = "Trojan:Win64/Amadey.PGAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b c1 4d 8d 5b 01 4d 0f 47 c7 4d 8d 52 01 33 d2 41 ff c1 41 f7 f6 42 0f b6 04 02 41 32 42 ff 41 88 43 ff 41 81 f9 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}