rule Trojan_Win32_BadJoke_EARZ_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.EARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 83 c2 02 d3 e8 32 c1 88 84 0d 78 56 fc ff 41 81 fa 38 53 07 00 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}