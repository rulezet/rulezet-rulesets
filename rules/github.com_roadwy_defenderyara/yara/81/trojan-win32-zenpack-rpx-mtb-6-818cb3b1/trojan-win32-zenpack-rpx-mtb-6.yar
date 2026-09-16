rule Trojan_Win32_Zenpack_RPX_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 85 80 fc ff ff ff d1 83 ec 0c 8b 8d cc fc ff ff 66 81 39 45 00 0f 94 c3 8b 95 bc fc ff ff 66 81 3a 4c 00 0f 94 c7 20 fb 8b b5 b8 fc ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}