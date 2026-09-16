rule Trojan_Win32_Staser_RK_MTB_2{
	meta:
		description = "Trojan:Win32/Staser.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 6a 06 58 ff 75 08 57 90 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}