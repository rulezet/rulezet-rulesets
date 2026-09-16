rule Trojan_Win32_Redline_MG_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 bf 37 00 00 00 f7 ff 8b 45 08 0f be 14 10 6b d2 34 83 e2 13 83 e2 51 33 f2 03 ce 8b 45 0c 03 45 fc 88 08 0f be 4d fb 8b 55 0c 03 55 fc 0f be 02 2b c1 8b 4d 0c 03 4d fc 88 01 eb } 		$a_01_1 = {73 68 46 6c 65 45 6a 4f 42 66 52 32 4c 48 41 48 35 45 64 64 65 67 4b 68 4e 30 4f 34 6a 58 64 79 52 63 78 75 56 70 62 4c 32 69 31 48 73 57 75 6d 59 42 4d 51 43 43 35 50 58 6d 69 33 4c 6b 35 6b 35 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}