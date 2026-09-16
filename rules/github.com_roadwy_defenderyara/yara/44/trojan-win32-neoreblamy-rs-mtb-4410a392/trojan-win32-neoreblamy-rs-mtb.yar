rule Trojan_Win32_Neoreblamy_RS_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 45 f8 ff 31 8b 45 fc 83 c0 0c 68 44 b3 06 10 89 45 fc ff 30 6a 03 68 51 03 00 00 56 e8 8d fd ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}