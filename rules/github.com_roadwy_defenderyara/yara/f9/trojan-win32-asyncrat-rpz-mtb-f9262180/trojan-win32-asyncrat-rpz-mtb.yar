rule Trojan_Win32_AsyncRat_RPZ_MTB{
	meta:
		description = "Trojan:Win32/AsyncRat.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d6 ff b5 98 fb ff ff ff d6 0f 57 c0 c7 85 ec fb ff ff 00 00 00 00 8d 95 c0 fb ff ff 66 0f d6 85 e4 fb ff ff 8d 8d e4 fb ff ff e8 ?? ?? ?? ?? c6 45 fc 04 8b 85 e8 fb ff ff 2b 85 e4 fb ff ff 6a 40 68 00 10 00 00 50 6a 00 ff 15 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}