rule Trojan_Win32_Glupteba_GMZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 06 89 d2 81 c6 01 00 00 00 39 de 75 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}