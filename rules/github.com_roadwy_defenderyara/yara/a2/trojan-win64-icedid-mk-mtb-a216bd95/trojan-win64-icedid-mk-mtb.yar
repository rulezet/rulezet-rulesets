rule Trojan_Win64_Icedid_MK_MTB{
	meta:
		description = "Trojan:Win64/Icedid.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 88 04 1b 83 e1 07 8b 44 95 e0 49 ff c3 d3 c8 ff c0 89 44 95 e0 83 e0 07 8a c8 42 8b 44 85 e0 d3 c8 ff c0 42 89 44 85 e0 48 8b 5d c8 4c 3b 5d d0 73 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}