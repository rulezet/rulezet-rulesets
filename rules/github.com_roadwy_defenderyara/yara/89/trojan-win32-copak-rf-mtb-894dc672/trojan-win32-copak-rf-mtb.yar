rule Trojan_Win32_Copak_RF_MTB{
	meta:
		description = "Trojan:Win32/Copak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 a0 36 4b 00 c3 [0-09] 52 ca 4e 00 [0-30] 31 } 		$a_01_1 = {09 f6 c3 09 db 21 f3 81 eb f2 ce 6b ed } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}