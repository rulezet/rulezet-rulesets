rule Trojan_Win32_Glupteba_GMZ_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 07 51 5b 81 c7 04 00 00 00 39 f7 ?? ?? 21 da c3 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}