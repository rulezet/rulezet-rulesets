rule Trojan_Win32_Glupteba_RPB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 16 41 4f 46 bf ?? ?? ?? ?? 39 de 75 e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}