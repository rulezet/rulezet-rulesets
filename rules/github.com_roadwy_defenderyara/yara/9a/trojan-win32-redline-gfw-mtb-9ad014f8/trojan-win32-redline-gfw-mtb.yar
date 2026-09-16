rule Trojan_Win32_Redline_GFW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 4d 80 0f b6 55 d7 f7 d2 8b 45 b8 33 c2 03 45 ac f7 d8 1b c0 83 c0 ?? 66 a3 ?? ?? ?? ?? 0f be 45 83 99 52 50 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}