rule Trojan_Win32_Amadey_AMY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 69 f6 91 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 91 e9 d1 5b 33 f1 3b d3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}