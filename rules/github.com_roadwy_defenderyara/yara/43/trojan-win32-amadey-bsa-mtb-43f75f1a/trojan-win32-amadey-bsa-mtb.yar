rule Trojan_Win32_Amadey_BSA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {be 58 9a d7 7f 4e 81 f6 76 ab 9f 6d 81 ee 74 7c ab 58 81 c6 77 86 3f 67 81 ce da 03 be 6b 81 ee fa 3b fe 6b 01 f7 5e 83 ef 04 87 3c 24 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}