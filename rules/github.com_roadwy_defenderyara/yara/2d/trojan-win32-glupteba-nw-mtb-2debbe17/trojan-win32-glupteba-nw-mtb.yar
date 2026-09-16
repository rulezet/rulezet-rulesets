rule Trojan_Win32_Glupteba_NW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {39 db 74 01 ea 31 0f 81 c7 04 00 00 00 39 df } 		$a_01_1 = {31 0f 81 c7 04 00 00 00 39 df 75 ef } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}