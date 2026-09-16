rule Trojan_Win32_Zusy_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d c0 33 c0 8b 5d 0c c7 42 40 00 00 00 00 8a 04 10 30 04 19 41 ff 42 40 8b 42 40 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}