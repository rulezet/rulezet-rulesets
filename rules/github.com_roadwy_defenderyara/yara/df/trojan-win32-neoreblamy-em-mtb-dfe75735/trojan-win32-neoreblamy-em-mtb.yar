rule Trojan_Win32_Neoreblamy_EM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 59 8b 4d f8 8b 09 03 c1 99 b9 07 ca 9a 3b f7 f9 8b 45 f8 89 10 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}