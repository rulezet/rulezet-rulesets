rule Trojan_Win32_Ekstak_ASEB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 6b c6 61 00 dd 29 5e 00 00 c0 0a 00 0d 15 b6 76 68 } 		$a_01_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 3e bf 61 00 b0 22 5e 00 00 c0 0a 00 0d 15 b6 76 31 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}