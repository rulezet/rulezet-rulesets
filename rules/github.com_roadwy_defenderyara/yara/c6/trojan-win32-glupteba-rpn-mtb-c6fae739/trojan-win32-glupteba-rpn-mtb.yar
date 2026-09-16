rule Trojan_Win32_Glupteba_RPN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {39 db 74 01 ea 31 17 [0-10] 81 c7 04 00 00 00 [0-10] 39 c7 75 e6 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}