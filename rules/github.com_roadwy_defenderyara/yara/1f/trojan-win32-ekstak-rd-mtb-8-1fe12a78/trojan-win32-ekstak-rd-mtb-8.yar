rule Trojan_Win32_Ekstak_RD_MTB_8{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce 8b 7d 04 03 cf 8b e8 03 00 0c 3b cd 75 05 ?? ?? ?? ?? 2a 8b ?? ?? ?? ?? 00 0c 24 8b 7b 08 03 7b 0c 2c f9 89 7c 24 04 2b 00 89 73 0c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}