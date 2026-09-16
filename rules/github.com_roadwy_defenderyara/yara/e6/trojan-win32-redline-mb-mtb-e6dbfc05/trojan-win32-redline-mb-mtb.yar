rule Trojan_Win32_Redline_MB_MTB{
	meta:
		description = "Trojan:Win32/Redline.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c0 f6 17 80 07 ?? 80 2f ?? f6 2f 47 e2 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}