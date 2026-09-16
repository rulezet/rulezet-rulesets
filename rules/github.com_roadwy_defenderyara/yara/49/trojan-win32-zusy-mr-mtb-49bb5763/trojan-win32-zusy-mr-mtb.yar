rule Trojan_Win32_Zusy_MR_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b ec 83 c4 b0 8b 45 10 40 8a 10 80 fa 20 } 		$a_01_1 = {68 fa 00 00 00 68 29 30 40 00 6a ff 68 23 31 40 00 6a 00 6a 00 } 	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*10) >=35
 
}