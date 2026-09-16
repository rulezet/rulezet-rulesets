rule Trojan_Win32_Remcos_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Remcos.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5b 0f b6 8d 52 fc ff ff 8b 95 68 f8 ff ff 0f be 02 2b c1 8b 8d 68 f8 ff ff 88 01 eb 95 8b 95 4c f5 ff ff 89 95 20 e6 ff ff 8d 85 18 f3 ff ff 50 8b 8d 18 f3 ff ff 51 8b 95 6c e9 ff ff 52 8b 85 18 fc ff ff 50 ff 95 20 e6 ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}