rule Trojan_Win32_Redline_MK_MTB{
	meta:
		description = "Trojan:Win32/Redline.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 17 80 07 ?? 80 2f ?? f6 2f 47 e2 f3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}