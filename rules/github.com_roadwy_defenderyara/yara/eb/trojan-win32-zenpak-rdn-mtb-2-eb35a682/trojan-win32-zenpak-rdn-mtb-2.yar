rule Trojan_Win32_Zenpak_RDN_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 39 53 0f 94 c3 8b 95 e4 fe ff ff 80 3a 54 0f 94 c7 20 fb } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}