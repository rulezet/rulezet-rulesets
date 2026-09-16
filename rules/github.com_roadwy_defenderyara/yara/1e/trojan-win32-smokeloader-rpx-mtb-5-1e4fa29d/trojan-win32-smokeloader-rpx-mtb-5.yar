rule Trojan_Win32_SmokeLoader_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 04 8d 8d 78 ff ff ff 51 8b 8f a4 00 00 00 83 c1 08 51 ff 75 90 ff d0 8b 45 ac 6a 40 68 00 30 00 00 8d 88 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}