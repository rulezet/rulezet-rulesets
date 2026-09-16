rule Trojan_Win32_GCleaner_BO_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c 53 56 57 8b 45 14 50 e8 4e 54 04 00 e9 } 		$a_01_1 = {ec 83 ec 0c 53 56 57 8b 45 14 50 e8 02 54 04 00 e9 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}