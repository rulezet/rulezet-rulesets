rule Trojan_Win64_Lazy_ABL_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 0f b6 42 01 4d 8d 52 01 0f b6 c0 48 05 00 01 00 00 48 c1 e0 08 48 03 c3 41 0f b6 0c 00 41 0f b6 c0 41 88 4a ff 49 83 eb 01 } 		$a_01_1 = {34 98 88 45 ec 0f b6 41 1d 34 e9 88 45 ed 0f b6 41 1e 34 6f 88 45 ee 0f b6 41 1f 34 b4 88 45 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}