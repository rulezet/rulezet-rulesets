rule Trojan_Win32_UrSnif_RPH_MTB{
	meta:
		description = "Trojan:Win32/UrSnif.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 31 37 47 81 e8 01 00 00 00 48 39 d7 75 e6 81 e9 01 00 00 00 [0-20] c3 8d 34 1e 01 c0 8b 36 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}