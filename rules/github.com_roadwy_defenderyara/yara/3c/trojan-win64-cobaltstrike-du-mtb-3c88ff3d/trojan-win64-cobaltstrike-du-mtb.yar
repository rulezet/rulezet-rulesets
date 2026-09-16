rule Trojan_Win64_Cobaltstrike_DU_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 fe c2 48 8d 5b 01 45 0f b6 d2 4f 8d 04 93 45 8b 48 08 41 02 c1 0f b6 c0 41 8b 54 83 08 41 89 50 08 41 02 d1 45 89 4c 83 08 0f b6 ca 41 0f b6 54 8b 08 30 53 ff 48 ff cf 75 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}