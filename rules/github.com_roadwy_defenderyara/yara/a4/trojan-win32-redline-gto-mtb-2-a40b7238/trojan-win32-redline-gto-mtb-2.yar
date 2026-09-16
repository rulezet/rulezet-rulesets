rule Trojan_Win32_Redline_GTO_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2a 4c 05 dc 80 f1 c8 d0 c1 02 c8 f6 d1 32 c8 80 c1 ?? 80 f1 ef 02 c8 32 c8 80 c1 ?? 32 c8 80 e9 ?? c0 c1 ?? 88 4c 05 dc 40 83 f8 0f 72 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}