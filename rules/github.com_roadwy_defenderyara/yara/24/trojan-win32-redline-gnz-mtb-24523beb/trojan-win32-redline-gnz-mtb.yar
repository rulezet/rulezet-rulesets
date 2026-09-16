rule Trojan_Win32_Redline_GNZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 33 c0 f6 17 80 37 ?? 47 e2 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}