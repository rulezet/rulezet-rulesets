rule Trojan_Win32_Zusy_EH_MTB{
	meta:
		description = "Trojan:Win32/Zusy.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {3f 50 57 89 e7 81 c7 04 00 00 00 83 ef 04 87 3c 24 8b 24 24 89 04 24 89 2c 24 58 e9 0c e3 ff ff ff 34 24 5b 53 54 5b 81 c3 04 00 00 00 81 c3 04 00 00 00 87 1c 24 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}