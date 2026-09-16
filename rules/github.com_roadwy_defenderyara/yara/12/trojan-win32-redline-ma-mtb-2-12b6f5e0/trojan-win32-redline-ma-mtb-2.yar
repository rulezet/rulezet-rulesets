rule Trojan_Win32_Redline_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 99 b9 ?? ?? ?? ?? f7 f9 8b 45 08 0f be 0c 10 69 c9 ?? ?? ?? ?? 83 e1 ?? 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 eb } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}