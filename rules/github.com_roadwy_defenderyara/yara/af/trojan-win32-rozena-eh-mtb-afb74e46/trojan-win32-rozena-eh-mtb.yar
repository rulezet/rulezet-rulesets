rule Trojan_Win32_Rozena_EH_MTB{
	meta:
		description = "Trojan:Win32/Rozena.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {d9 74 24 f4 5b 31 c9 66 b9 3b 55 31 53 1c 83 c3 04 03 53 18 e2 } 		$a_01_1 = {d9 74 24 f4 5e 2b c9 66 b9 3b 55 83 ee fc 31 5e 13 03 5e 13 e2 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}