rule Trojan_Win32_Redline_RPW_MTB{
	meta:
		description = "Trojan:Win32/Redline.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 07 9f fe 07 47 e2 f6 5f 5e 5b 5d c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}