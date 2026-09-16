rule Trojan_Win32_Tepfer_BAD_MTB_2{
	meta:
		description = "Trojan:Win32/Tepfer.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 00 10 00 00 8b 55 ?? 03 55 ?? 2b d0 83 c2 04 89 55 ?? b8 6a 0a 00 00 ff 75 ?? b8 6a 0a 00 00 ff 75 ?? b8 6a 0a 00 00 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}