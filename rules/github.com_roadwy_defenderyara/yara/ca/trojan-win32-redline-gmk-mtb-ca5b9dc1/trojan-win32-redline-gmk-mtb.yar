rule Trojan_Win32_Redline_GMK_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 33 83 ff 0f ?? ?? 6a 00 ff d5 6a 2e 8d 44 24 10 6a 00 50 c7 44 24 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}