rule Trojan_Win32_Fareit_OP_MTB{
	meta:
		description = "Trojan:Win32/Fareit.OP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 89 45 f4 8b 45 fc 90 03 45 f8 90 8a 18 90 80 f3 e6 88 18 90 90 ff 45 f8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}