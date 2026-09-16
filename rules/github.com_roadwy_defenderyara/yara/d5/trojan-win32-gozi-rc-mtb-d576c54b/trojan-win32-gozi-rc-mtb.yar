rule Trojan_Win32_Gozi_RC_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 44 01 fd 89 45 fc 8b 75 f0 2b ff 81 ef 75 03 00 00 03 ff ff e6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}