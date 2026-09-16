rule Trojan_Win64_Rozena_NM_MTB_3{
	meta:
		description = "Trojan:Win64/Rozena.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 45 33 c0 ba ?? ?? ?? ?? 48 8b c8 e8 6d 15 f3 ff 48 8b 44 24 } 		$a_03_1 = {eb 0a 8b 44 24 30 ff c0 89 44 24 ?? 48 63 44 24 ?? 48 83 f8 05 73 11 48 63 44 24 ?? 48 8b 4c 24 ?? c6 44 01 3e 00 eb da e9 fa fe ff ff 48 8d 4c 24 ?? e8 50 18 f3 ff 48 89 44 24 ?? 48 8d 4c 24 ?? e8 16 fd f2 ff } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}