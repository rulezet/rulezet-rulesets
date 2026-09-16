rule Trojan_Win32_Redline_DE_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d a3 0f b6 55 a3 33 55 a4 88 55 a3 0f b6 45 a3 2b 45 a4 88 45 a3 0f b6 4d a3 f7 d1 88 4d a3 0f b6 55 a3 33 55 a4 88 55 a3 0f b6 45 a3 f7 d0 88 45 a3 0f b6 4d a3 33 4d a4 88 4d a3 8b 55 a4 8a 45 a3 88 44 15 b0 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}