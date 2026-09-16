rule Trojan_Win32_Glupteba_NG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 0f 81 ea ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 89 d6 89 da 39 c7 75 e5 c3 09 d6 ?? ?? 81 c2 ?? ?? ?? ?? 21 d2 c3 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}