rule Trojan_Win32_Glupteba_QP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {be d8 85 40 00 09 c0 e8 ?? ?? ?? ?? 31 33 43 68 ?? ?? ?? ?? 58 48 39 d3 75 e6 48 21 f8 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}