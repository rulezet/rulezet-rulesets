rule Trojan_Win32_Staser_RK_MTB_4{
	meta:
		description = "Trojan:Win32/Staser.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 14 50 ff 15 78 66 65 00 6a 00 6a 00 ff 15 9c 66 65 00 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}