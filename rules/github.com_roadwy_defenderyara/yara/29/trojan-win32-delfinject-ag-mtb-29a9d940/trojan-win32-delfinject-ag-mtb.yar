rule Trojan_Win32_DelfInject_AG_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 6c 11 fc 01 c5 89 6c 13 04 83 c2 04 81 fa fc 4f 00 00 72 eb } 		$a_01_1 = {a1 60 ca 8d 00 89 43 08 56 ff 74 24 04 68 00 50 00 00 53 ff d7 a1 7c ca 8d 00 01 d8 03 43 0c 03 1d 7c ca 8d 00 53 ff d0 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}