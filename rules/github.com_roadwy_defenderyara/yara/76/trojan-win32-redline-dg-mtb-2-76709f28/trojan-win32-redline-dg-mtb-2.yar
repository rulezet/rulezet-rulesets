rule Trojan_Win32_Redline_DG_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d db 0f b6 55 db f7 da 88 55 db 0f b6 45 db c1 f8 06 0f b6 4d db c1 e1 02 0b c1 88 45 db 0f b6 55 db f7 da 88 55 db 0f b6 45 db f7 d0 88 45 db 0f b6 4d db 83 e9 28 88 4d db } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}