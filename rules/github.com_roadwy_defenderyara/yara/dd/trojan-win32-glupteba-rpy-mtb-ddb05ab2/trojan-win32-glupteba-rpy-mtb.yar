rule Trojan_Win32_Glupteba_RPY_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 17 09 db 89 f3 47 4e 39 cf 75 e3 c3 81 eb 01 00 00 00 09 db 8d 14 02 8b 12 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}