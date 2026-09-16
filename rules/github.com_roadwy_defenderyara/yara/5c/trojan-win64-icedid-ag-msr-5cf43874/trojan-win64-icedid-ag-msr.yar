rule Trojan_Win64_IcedID_AG_MSR{
	meta:
		description = "Trojan:Win64/IcedID.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 66 3b c0 74 b8 e6 c4 90 ff d1 48 c1 ed 97 90 48 f7 f4 48 f7 f7 48 81 f9 d6 16 00 00 48 ff cb 48 81 d6 3d 0d 00 00 49 ff c4 48 85 dd e6 25 49 f7 d6 48 ff c3 48 f7 e6 4d 33 c0 49 f7 f8 41 5c e4 eb 49 ff c8 4d 23 c9 48 33 ff 48 81 f9 01 08 00 00 41 5a 49 f7 fa e6 9b ff d2 48 69 ff d1 26 00 00 49 8b f2 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}