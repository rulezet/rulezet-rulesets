rule Trojan_Win32_Ursnif_GA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 01 8a 54 24 0c 32 d0 41 88 16 46 ff 4c 24 08 75 ee } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}