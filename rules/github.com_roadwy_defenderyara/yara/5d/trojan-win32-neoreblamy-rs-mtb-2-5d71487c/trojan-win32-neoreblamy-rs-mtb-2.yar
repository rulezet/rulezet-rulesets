rule Trojan_Win32_Neoreblamy_RS_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be f0 33 d2 0f be c3 03 45 fc 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce 40 89 4d f8 89 45 fc 39 47 10 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}