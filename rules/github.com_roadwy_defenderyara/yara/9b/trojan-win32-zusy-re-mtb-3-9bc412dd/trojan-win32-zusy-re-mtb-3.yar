rule Trojan_Win32_Zusy_RE_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 04 3a 8b 18 89 ce 31 de 89 30 8d 47 04 89 c7 3b 7d fc 72 eb } 		$a_01_1 = {67 77 59 39 62 4d 55 63 63 67 67 67 68 51 46 34 6a 75 42 4b 51 37 49 6f 75 47 6b 79 50 52 70 65 69 70 35 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}