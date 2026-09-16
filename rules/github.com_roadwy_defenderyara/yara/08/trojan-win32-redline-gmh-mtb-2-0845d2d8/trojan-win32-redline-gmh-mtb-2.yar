rule Trojan_Win32_Redline_GMH_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f3 33 db 8b f6 8b f3 f6 17 33 c6 8b de 8b c0 80 07 ?? 8b c6 8b c0 8b db 80 2f ?? 33 c6 33 c3 33 db f6 2f 47 e2 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}