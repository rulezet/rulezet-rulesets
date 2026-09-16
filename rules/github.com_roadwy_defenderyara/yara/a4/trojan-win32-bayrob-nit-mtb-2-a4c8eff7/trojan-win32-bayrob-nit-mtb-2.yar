rule Trojan_Win32_Bayrob_NIT_MTB_2{
	meta:
		description = "Trojan:Win32/Bayrob.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 7c 31 ff ff 6a 02 5e 89 30 e8 3e 31 ff ff 89 30 e9 d2 03 00 00 66 83 7b 02 3a 75 1d 0f b7 03 66 85 c0 74 06 66 39 73 04 74 d5 50 e8 0f ef ff ff } 		$a_01_1 = {89 b5 b0 fb ff ff 89 b5 b4 fb ff ff e8 63 82 00 00 83 c4 1c 89 47 1c 89 47 18 89 47 20 e9 31 02 00 00 39 b5 90 fb ff ff 0f 84 c8 fe ff ff ff b5 90 fb ff ff e8 1c 16 ff ff } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}