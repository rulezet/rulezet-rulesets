rule Trojan_Win32_Azorult_EH_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f0 8b d6 c1 e2 04 89 44 24 14 89 54 24 10 8b 44 24 2c 01 44 24 10 8b c6 c1 e8 05 03 c5 03 fe } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}