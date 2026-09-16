rule Trojan_Win32_Redline_GJP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c2 83 e2 03 0f b6 92 20 74 45 00 30 90 20 c8 43 00 83 c0 01 3d 00 ac 01 00 75 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}