rule Trojan_Win32_Zusy_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 02 4b 81 c2 04 00 00 00 bb 90 ae f3 c2 21 d9 39 fa 75 e7 21 f3 c3 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}