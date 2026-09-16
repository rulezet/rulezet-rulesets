rule Trojan_Win64_Lazy_RC_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 ba 00 10 00 00 00 00 00 00 49 b8 ?? ?? 00 00 00 00 00 00 65 48 8b 04 25 60 00 00 00 48 8b 40 10 48 01 c2 49 01 c0 4c 8b ca 48 31 0a 48 83 c2 08 49 3b d0 72 f4 41 ff e1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}