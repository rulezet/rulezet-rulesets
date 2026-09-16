rule Trojan_Win32_Razy_ARA_MTB{
	meta:
		description = "Trojan:Win32/Razy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 11 8a 00 8b 4d 10 03 c2 25 ff 00 00 00 03 cf 8a 84 05 fc fe ff ff 30 01 47 3b 7d 14 7c } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}