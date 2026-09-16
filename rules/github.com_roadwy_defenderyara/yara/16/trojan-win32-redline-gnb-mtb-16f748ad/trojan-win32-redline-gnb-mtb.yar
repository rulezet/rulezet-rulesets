rule Trojan_Win32_Redline_GNB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 80 34 3e ?? 83 c4 28 46 3b 74 24 18 0f 82 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}