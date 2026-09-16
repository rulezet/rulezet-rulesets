rule Trojan_Win32_Glupteba_GMZ_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 ca 31 3e 29 c2 40 f7 d2 46 21 c9 29 c8 48 43 21 d0 48 81 fe } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}