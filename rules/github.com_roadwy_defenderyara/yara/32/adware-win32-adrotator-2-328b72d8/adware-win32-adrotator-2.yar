rule Adware_Win32_AdRotator_2{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 15 8b 15 ?? ?? ?? ?? 0f be cb 83 e9 28 8a 0c 0a 88 0f } 		$a_03_1 = {eb 19 8b 15 ?? ?? ?? ?? 0f be cb 83 e9 28 8a 0c 0a 8b 54 24 14 88 0a } 		$a_03_2 = {80 fb 28 7c ?? 80 fb 7e 7f ?? 85 c0 75 14 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*10) >=11
 
}