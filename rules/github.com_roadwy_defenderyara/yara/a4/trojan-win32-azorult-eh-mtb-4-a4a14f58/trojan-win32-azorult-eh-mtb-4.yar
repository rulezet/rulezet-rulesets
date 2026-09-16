rule Trojan_Win32_Azorult_EH_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f0 8b ce c1 e1 04 89 44 24 14 89 4c 24 10 8b 44 24 28 01 44 24 10 8b d6 c1 ea 05 03 d5 8d 04 37 31 44 24 10 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}