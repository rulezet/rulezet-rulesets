rule Trojan_Win32_Zenpack_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpack.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 85 9c fc ff ff ff d1 83 ec 0c 8b 8d a4 fc ff ff 66 81 39 53 00 0f 94 c3 8b 95 a0 fc ff ff 66 81 3a 45 00 0f 94 c7 20 fb 8b b5 b8 fc ff ff 66 81 3e 2e 00 0f 94 c7 20 fb 8b bd a8 fc ff ff 66 81 3f 4c 00 0f 94 c7 } 		$a_01_1 = {89 85 94 fc ff ff ff d1 83 ec 0c 8b 8d 9c fc ff ff 66 81 39 53 00 0f 94 c3 8b 95 98 fc ff ff 66 81 3a 45 00 0f 94 c7 20 fb 8b b5 b0 fc ff ff 66 81 3e 2e 00 0f 94 c7 20 fb 8b bd a0 fc ff ff 66 81 3f 4c 00 0f 94 c7 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}