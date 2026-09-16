rule Trojan_Win64_Lazy_ARR_MTB_3{
	meta:
		description = "Trojan:Win64/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {49 ff c1 42 0f b6 84 10 ?? ?? ?? ?? 42 32 84 11 ?? ?? ?? ?? 41 88 40 ff 41 81 fc } 		$a_03_1 = {42 0f b6 04 20 42 32 84 39 ?? ?? ?? ?? 41 88 01 41 ff c0 49 ff c2 4d 8d 49 } 		$a_03_2 = {ff c1 8b 45 ?? 99 f7 f9 89 45 00 e9 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*8+(#a_03_2  & 1)*2) >=20
 
}