rule Trojan_Win32_Remcos_BA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 08 8b c6 99 f7 f9 8a 04 1a 8b 55 f8 30 04 16 46 3b f7 7c } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}