rule Trojan_Win32_Redline_GJV_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 c0 09 d0 88 45 a7 8b 45 f0 00 45 a7 f6 5d a7 80 75 a7 73 8b 45 f0 28 45 a7 8b 45 f0 30 45 a7 f6 5d a7 80 6d a7 43 8d 55 84 8b 45 f0 01 c2 0f b6 45 a7 88 02 83 45 f0 01 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}