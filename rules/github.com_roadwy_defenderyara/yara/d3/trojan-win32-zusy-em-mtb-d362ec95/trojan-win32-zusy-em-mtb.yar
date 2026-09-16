rule Trojan_Win32_Zusy_EM_MTB{
	meta:
		description = "Trojan:Win32/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 d3 2b f9 2b c3 2b d1 33 cf 33 fa } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}