rule Trojan_Win32_Glupteba_RPX_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 ff be c6 ae cd 97 31 03 21 f6 43 39 cb } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}