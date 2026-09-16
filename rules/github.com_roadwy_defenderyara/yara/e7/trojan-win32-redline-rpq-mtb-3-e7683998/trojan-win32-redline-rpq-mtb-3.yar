rule Trojan_Win32_RedLine_RPQ_MTB_3{
	meta:
		description = "Trojan:Win32/RedLine.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 5c 24 10 0f b6 1c 03 32 18 83 c0 04 88 5c 28 fc 8b 5c 24 14 0f b6 1c 0b 32 58 fd 83 c1 04 88 59 fc 0f b6 58 fe 32 5f ff 83 c7 04 88 59 fd 0f b6 58 ff 32 5f fc 83 6c 24 18 01 88 59 fe 75 c0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}