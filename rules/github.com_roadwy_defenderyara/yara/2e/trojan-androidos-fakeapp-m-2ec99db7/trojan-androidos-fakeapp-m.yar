rule Trojan_AndroidOS_Fakeapp_M{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.M,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5a 57 70 6d 62 32 63 6a 4a 47 35 48 61 6d 4a 76 63 32 4a 6e 52 32 5a 76 5a 6e 64 6d 4a 43 4e 69 62 57 63 6a 62 6d 5a 33 61 32 78 6e 49 79 52 73 62 55 64 6d 62 32 5a 33 5a 69 51 } 		$a_01_1 = {5a 6d 31 79 64 6d 5a 32 5a 6c 64 73 59 6e 42 33 52 6e 73 } 		$a_01_2 = {5a 57 70 6d 62 32 63 6a 4a 47 35 48 61 6d 4a 76 63 32 4a 6e 53 6d 31 7a 64 6e 63 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}