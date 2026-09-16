rule Trojan_Win32_Redline_GMG_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d2 88 55 83 0f b6 45 83 05 ?? ?? ?? ?? 88 45 83 0f b6 4d 83 83 f1 5a 88 4d 83 0f b6 55 83 2b 55 84 88 55 83 0f b6 45 83 f7 d0 88 45 83 0f b6 4d 83 83 f1 67 88 4d 83 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}