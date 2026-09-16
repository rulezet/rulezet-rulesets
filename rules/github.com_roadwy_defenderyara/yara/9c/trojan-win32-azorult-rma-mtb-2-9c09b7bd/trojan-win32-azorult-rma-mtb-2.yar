rule Trojan_Win32_Azorult_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 bb 52 c0 5d 8b 55 ?? 8b 7d ?? 8b ca c1 e1 04 03 4d ?? 8b c2 c1 e8 05 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}