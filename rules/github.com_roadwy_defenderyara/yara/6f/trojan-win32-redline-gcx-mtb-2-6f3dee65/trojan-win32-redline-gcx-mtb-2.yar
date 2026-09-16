rule Trojan_Win32_Redline_GCX_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4d bf 8b 45 c0 33 d2 be ?? ?? ?? ?? f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d c7 8b 45 c0 8a 88 ?? ?? ?? ?? 88 4d be 0f b6 55 c7 8b 45 c0 0f b6 88 ?? ?? ?? ?? 03 ca 8b 55 c0 88 8a } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}