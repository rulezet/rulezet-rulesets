rule Trojan_Win32_FormBook_CA_MTB{
	meta:
		description = "Trojan:Win32/FormBook.CA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f0 00 84 d7 17 8b 45 e4 89 45 f4 83 7d f0 00 74 16 8b 45 f4 c6 00 00 8b 45 f4 40 89 45 f4 8b 45 f0 48 89 45 f0 eb e4 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}