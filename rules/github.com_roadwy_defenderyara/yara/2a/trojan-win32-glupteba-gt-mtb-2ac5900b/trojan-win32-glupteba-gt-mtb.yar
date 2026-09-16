rule Trojan_Win32_Glupteba_GT_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 0f 29 c0 21 d8 81 c7 04 00 00 00 39 f7 75 eb 42 81 c2 ?? ?? ?? ?? c3 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}