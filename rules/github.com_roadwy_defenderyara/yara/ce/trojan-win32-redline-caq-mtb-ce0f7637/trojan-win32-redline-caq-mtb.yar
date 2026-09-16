rule Trojan_Win32_RedLine_CAQ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.CAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e2 c1 ea 06 8b c2 c1 e0 06 03 c2 8b d1 2b d0 0f b6 82 [0-04] b2 1c f6 ea 24 45 30 46 01 83 c1 02 81 f9 7e 07 00 00 72 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}