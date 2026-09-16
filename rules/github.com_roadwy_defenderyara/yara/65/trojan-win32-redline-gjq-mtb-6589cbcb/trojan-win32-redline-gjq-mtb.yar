rule Trojan_Win32_Redline_GJQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 02 88 45 bf 0f b6 4d bf 8b 45 c0 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d c7 8b 45 08 03 45 c0 8a 08 88 4d be 8a 55 be 88 55 bd } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}