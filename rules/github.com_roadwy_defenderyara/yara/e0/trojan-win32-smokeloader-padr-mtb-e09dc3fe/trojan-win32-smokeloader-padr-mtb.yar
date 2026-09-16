rule Trojan_Win32_Smokeloader_PADR_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.PADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 89 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 30 14 1e 83 ff 0f 75 } 		$a_01_1 = {46 3b f7 7c ca } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}