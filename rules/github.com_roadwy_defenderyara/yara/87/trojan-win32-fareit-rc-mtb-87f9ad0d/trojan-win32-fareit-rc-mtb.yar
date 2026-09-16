rule Trojan_Win32_Fareit_RC_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 51 0c 8b 8d 78 ff ff ff 8b b5 70 ff ff ff 8a 04 08 32 04 32 8b 4d cc 8b 51 0c 8b 8d 68 ff ff ff 88 04 0a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}