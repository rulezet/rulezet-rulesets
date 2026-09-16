rule Trojan_Win32_Zenpak_RDN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff d1 83 ec 10 31 c9 89 ca 89 45 bc 89 55 c0 89 4d c4 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}