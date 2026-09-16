rule Trojan_Win32_RedLine_RDCN_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.RDCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 ce 6c f7 d7 c1 df 36 f7 d8 42 0f c8 81 c7 ce 00 00 00 f7 e8 f7 d3 0f ce c1 d2 99 f7 d7 c1 d6 74 f7 da } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}