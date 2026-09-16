rule Trojan_Win32_RedLine_RPX_MTB_6{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 fb 0f be 4d fb 0f be 75 fb 8b 45 fc 99 bf 37 00 00 00 f7 ff 8b 45 08 0f be 04 10 69 c0 53 0b 00 00 99 bf 34 00 00 00 f7 ff 25 70 29 00 00 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}