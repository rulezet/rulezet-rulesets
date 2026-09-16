rule Trojan_Win32_Glupteba_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 ff 75 d4 8b 45 fc ff 50 18 8b 55 fc 89 42 28 8d 45 d8 50 8b 45 fc ff 50 1c 8b 45 fc 8b 55 dc 89 50 38 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}