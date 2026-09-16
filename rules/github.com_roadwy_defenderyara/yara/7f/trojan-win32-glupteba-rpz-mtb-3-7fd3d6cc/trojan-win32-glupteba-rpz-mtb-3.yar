rule Trojan_Win32_Glupteba_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 df 31 32 47 42 43 39 c2 75 e0 81 c3 01 00 00 00 c3 81 eb 01 00 00 00 8d 34 0e } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}