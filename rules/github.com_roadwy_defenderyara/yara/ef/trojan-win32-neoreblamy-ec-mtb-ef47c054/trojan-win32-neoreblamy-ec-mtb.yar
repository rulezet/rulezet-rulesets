rule Trojan_Win32_Neoreblamy_EC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c6 6a 34 59 f7 f1 8b 45 08 8b 0c b3 8b 14 90 8b c1 23 c2 03 c0 2b c8 03 ca 89 0c b3 46 3b f7 72 dc } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}