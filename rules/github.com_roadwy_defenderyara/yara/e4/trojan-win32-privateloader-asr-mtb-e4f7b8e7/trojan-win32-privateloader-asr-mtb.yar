rule Trojan_Win32_Privateloader_ASR_MTB{
	meta:
		description = "Trojan:Win32/Privateloader.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 38 20 31 30 37 20 39 32 20 31 30 30 20 31 30 33 20 32 38 20 38 33 } 		$a_01_1 = {39 37 20 39 31 20 31 30 34 20 31 30 30 20 39 31 20 39 38 20 34 31 20 34 30 20 33 36 20 39 30 20 39 38 20 39 38 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}