rule Trojan_Win32_Cryptinject_DSK_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 10 73 ?? 8b 4d f8 8b 55 f4 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 8b 55 f4 83 c2 01 89 55 f4 eb } 		$a_00_1 = {48 66 73 64 66 67 6b 6a 35 33 } 		$a_00_2 = {48 66 73 64 66 4a 67 34 32 } 	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}