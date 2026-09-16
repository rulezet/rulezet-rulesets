rule Trojan_Win32_Redline_RJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e8 e9 c6 45 e9 29 c6 45 ea 35 c6 45 eb f4 c6 45 ec 73 c6 45 ed f5 c6 45 ee 66 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}