rule Trojan_Win32_Staser_RK_MTB_3{
	meta:
		description = "Trojan:Win32/Staser.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec ff 15 d8 63 65 00 6a ff 6a 00 6a 00 ff 15 c8 66 65 00 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}