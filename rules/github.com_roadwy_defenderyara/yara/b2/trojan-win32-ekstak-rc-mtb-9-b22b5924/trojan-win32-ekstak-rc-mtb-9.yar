rule Trojan_Win32_Ekstak_RC_MTB_9{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 33 c0 80 e2 3f 8a c2 0d c0 ff 00 00 83 c4 0c c3 90 90 90 90 55 8b ec ff 15 10 53 65 00 e8 82 ff ff ff e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}