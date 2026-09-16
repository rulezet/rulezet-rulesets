rule Trojan_Win32_Glupteba_PA_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 db 8a 93 ?? ?? ?? 00 30 11 43 81 fb 10 00 00 00 75 02 33 db 41 3b 0d 2c 80 48 00 75 } 		$a_02_1 = {33 db 3b 05 ?? ?? ?? 00 74 2a 3b 05 ?? ?? ?? 00 74 15 8a 93 ?? ?? ?? 00 30 10 43 81 fb 10 00 00 00 75 0e 33 db eb 0a 03 05 ?? ?? ?? 00 33 db eb ?? 40 eb } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}