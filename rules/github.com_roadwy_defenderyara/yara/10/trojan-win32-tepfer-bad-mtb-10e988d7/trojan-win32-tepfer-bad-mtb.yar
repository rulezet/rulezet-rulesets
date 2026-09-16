rule Trojan_Win32_Tepfer_BAD_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f8 8b 45 dc 31 38 83 45 ec 04 83 45 dc 04 8b 45 ec 3b 45 d8 72 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}