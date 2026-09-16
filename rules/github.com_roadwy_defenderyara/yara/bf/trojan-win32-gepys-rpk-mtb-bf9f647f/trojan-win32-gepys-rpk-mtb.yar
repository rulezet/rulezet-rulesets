rule Trojan_Win32_Gepys_RPK_MTB{
	meta:
		description = "Trojan:Win32/Gepys.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af 4d 10 29 ca 03 55 08 ff 4d f0 8a 0a 88 4d db 8a 08 88 0a 8a 55 db 88 10 75 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}