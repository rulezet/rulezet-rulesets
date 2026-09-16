rule Trojan_Win32_VBInject_BSA_MTB{
	meta:
		description = "Trojan:Win32/VBInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 64 61 72 6b 20 65 79 65 5c 44 61 72 6b 20 45 59 45 } 		$a_81_1 = {76 65 72 6d 69 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1) >=10
 
}