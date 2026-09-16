rule Trojan_Win32_Fareit_SS_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 75 fc 03 f7 8a 03 88 45 fb 8b c7 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 fb 32 45 fa 88 06 8a 06 32 45 f9 88 06 eb 05 8a 45 fb 88 06 47 43 49 75 ca } 		$a_02_1 = {75 11 8a 45 ?? 32 45 ?? 88 06 8a 06 32 45 ?? 88 06 eb 05 8a 45 ?? 88 06 47 43 49 75 ca } 		$a_00_2 = {8b 75 fc 03 f7 8a 03 88 45 fa 8b c7 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 fa 32 45 fb 88 06 8a 06 32 45 f9 88 06 eb 05 8a 45 fa 88 06 47 43 49 75 ca } 	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*1+(#a_00_2  & 1)*2) >=2
 
}