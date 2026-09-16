rule Trojan_Win32_Amadey_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Amadey.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 fc 06 8d 95 d0 fc ff ff 83 bd e4 fc ff ff 08 8d bd d0 fc ff ff 8b 85 e0 fc ff ff 8d 8d b0 fc ff ff 0f 43 95 d0 fc ff ff 0f 43 bd d0 fc ff ff c7 85 c0 fc ff ff 00 00 00 00 c7 85 c4 fc ff ff 0f 00 00 00 8d 1c 42 c6 85 b0 fc ff ff 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}